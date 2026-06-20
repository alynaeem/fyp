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

