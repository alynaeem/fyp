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

