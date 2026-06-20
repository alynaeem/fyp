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

