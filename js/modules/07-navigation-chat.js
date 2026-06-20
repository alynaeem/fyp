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

