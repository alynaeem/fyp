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

