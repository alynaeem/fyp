import { PAGINATION_WINDOW, TAB_SOURCE_MAP, TRANSLATION_OPTIONS } from "../core/config.js";
import { state } from "../state/appState.js";

export const $ = id => document.getElementById(id);

export function debounce(fn, wait) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), wait);
  };
}

export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

export function normalizePreviewText(value, fallback = "") {
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

export function getBlankFeedFilters() {
  return {
    startDate: "",
    endDate: "",
    topic: ""
  };
}

export function normalizeFeedFilters(filters = {}) {
  return {
    startDate: String(filters.startDate || "").trim(),
    endDate: String(filters.endDate || "").trim(),
    topic: String(filters.topic || "").trim()
  };
}

export function currentSourceType() {
  return TAB_SOURCE_MAP[state.activeTab] || state.activeTab || "all";
}

export function buildFeedSnapshotKeyFor(sourceType = currentSourceType(), query = "", filters = getBlankFeedFilters(), page = state.feedPage || 1) {
  const normalizedFilters = normalizeFeedFilters(filters);
  const filterKey = [
    normalizedFilters.startDate,
    normalizedFilters.endDate,
    normalizedFilters.topic
  ].join("|");
  return `${String(sourceType || "all").trim().toLowerCase()}::${String(query || "").trim().toLowerCase()}::filters:${filterKey}::page:${page}`;
}

export function buildFeedSnapshotKey(page = state.feedPage || 1) {
  const query = $("searchInput")?.value.trim().toLowerCase() || "";
  return buildFeedSnapshotKeyFor(currentSourceType(), query, state.feedFilters, page);
}

export function getTranslationLabel(code) {
  return TRANSLATION_OPTIONS.find(option => option.code === code)?.label || code.toUpperCase();
}

export function shouldTranslateText(text) {
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

export function formatDate(value) {
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

export function humanViewName(viewName) {
  return viewName;
}

export function firstNonEmpty(...values) {
  return values.find(value => String(value ?? "").trim()) || "";
}

export function hostFromValue(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  try {
    return new URL(text).hostname || text;
  } catch {
    return text;
  }
}

export function formatShortDate(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text;
  const parsed = new Date(text);
  if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleDateString();
  return text;
}

export function slugifyFilename(value, fallback = "darkpulse-export") {
  const normalized = String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || fallback;
}

export function formatExportTimestamp(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${year}${month}${day}-${hours}${minutes}${seconds}`;
}

export function formatExportValue(value) {
  if (Array.isArray(value)) {
    return value.map(item => formatExportValue(item)).filter(Boolean).join(", ");
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  const text = String(value ?? "").trim();
  return text || "-";
}
