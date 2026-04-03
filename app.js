const DEFAULT_API_BASE = window.location.origin && window.location.origin !== "null"
  ? window.location.origin
  : "http://localhost:8200";

const STORAGE_KEY = "darkpulse_api_key";
const TOKEN_KEY = "darkpulse_token";
const USER_ROLE_KEY = "darkpulse_role";
const USER_NAME_KEY = "darkpulse_name";
const API_BASE_KEY = "darkpulse_base";
const PAGE_SIZE = 36;
const REFRESH_MS = 2 * 60 * 1000;
const SEARCH_DEBOUNCE_MS = 280;

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
  pakdb: {
    title: "PakDB Lookup",
    subtitle: "Search entity and phone data live from the connected backend."
  },
  "admin-users": {
    title: "User Management",
    subtitle: "Approve, reject, and review dashboard access."
  }
};

const state = {
  activeTab: "all",
  currentView: "homepage",
  offset: 0,
  total: 0,
  isRegistering: false,
  refreshTimer: null,
  mapInstance: null,
  detailCache: new Map(),
  countryStatsByCode: {}
};

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

function updateHeader(viewName) {
  const meta = VIEW_META[viewName] || VIEW_META.all;
  $("viewTitle").textContent = meta.title;
  $("viewSubtitle").textContent = meta.subtitle;
}

function setLastUpdated() {
  $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
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
    body: options.body ? JSON.stringify(options.body) : undefined
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

function handleLogout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_ROLE_KEY);
  localStorage.removeItem(USER_NAME_KEY);
  window.location.reload();
}

function toggleAuthMode() {
  state.isRegistering = !state.isRegistering;
  $("loginForm").classList.toggle("hidden", state.isRegistering);
  $("registerForm").classList.toggle("hidden", !state.isRegistering);
  $("authSubmitBtn").textContent = state.isRegistering ? "Request Access" : "Sign In";
}

function showError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearErrors() {
  ["loginError", "registerError"].forEach(id => {
    $(id).textContent = "";
    $(id).classList.add("hidden");
  });
}

async function handleAuthSubmit() {
  clearErrors();
  const button = $("authSubmitBtn");
  const originalLabel = button.textContent;
  button.disabled = true;

  try {
    if (state.isRegistering) {
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

    const data = await apiFetch("/auth/login", true, {
      method: "POST",
      body: {
        username: $("loginUsername").value.trim(),
        password: $("loginPassword").value
      }
    });

    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_ROLE_KEY, data.role);
    localStorage.setItem(USER_NAME_KEY, $("loginUsername").value.trim());
    window.location.reload();
  } catch (error) {
    showError(state.isRegistering ? "registerError" : "loginError", error.message);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
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

  countries.slice(0, 18).forEach(country => {
    const row = document.createElement("div");
    row.className = "country-row";
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

async function initHeatmap() {
  const payload = await apiFetch("/stats/map");
  const countries = payload.countries || [];

  $("impactCountriesCount").textContent = String(payload.summary?.affected_countries || countries.length || 0);
  $("impactLeakCoverage").textContent = String(payload.summary?.leak_items_with_country || 0);
  $("impactDefaceCoverage").textContent = String(payload.summary?.defacement_items_with_country || 0);

  renderCountryImpactList(countries);
  state.countryStatsByCode = Object.fromEntries(countries.map(country => [country.code, country]));

  const mapValues = payload.map_data || {};
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
        fill: "#18202f",
        stroke: "#242f44",
        strokeWidth: 0.5
      },
      hover: {
        fill: "#ff6b57",
        cursor: "pointer"
      }
    },
    series: {
      regions: [{
        values: mapValues,
        scale: ["#2b1115", "#7f1d1d", "#ef4444"],
        normalizeFunction: "polynomial"
      }]
    },
    onRegionTooltipShow(event, tooltip, code) {
      const stats = state.countryStatsByCode[code];
      if (!stats) {
        tooltip.text(`${tooltip.text()} - no mapped leak or defacement count`);
        return;
      }
      tooltip.html(`
        <div>
          <strong>${escapeHtml(stats.name)}</strong><br>
          Leak count: ${stats.leak_count}<br>
          Defacement count: ${stats.defacement_count}<br>
          Total impact: ${stats.total}
        </div>
      `);
    }
  });
}

function createCompactItem(item) {
  const element = document.createElement("div");
  element.className = "compact-item";
  element.addEventListener("click", () => showDetail(item.aid));
  element.innerHTML = `
    <div class="compact-item-header">
      <span class="compact-badge">${escapeHtml(item.source_type || "intel")}</span>
      <span class="compact-meta">${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    </div>
    <div class="compact-title">${escapeHtml(item.title || "Untitled")}</div>
    <div class="compact-item-footer">
      <span class="compact-meta">${escapeHtml(item.source || "Unknown source")}</span>
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
  card.addEventListener("click", () => showDetail(item.aid));

  const countryText = (item.country_names || []).join(", ");
  const metaChips = [
    buildCardChip("Author", item.author),
    buildCardChip("Country", countryText),
    buildCardChip("IPs", item.ip_addresses),
    buildCardChip("Attacker", item.attacker),
    buildCardChip("Team", item.team),
    buildCardChip("Server", item.web_server)
  ].filter(Boolean).join("");

  const categories = Array.isArray(item.categories)
    ? item.categories.slice(0, 3).map(category => escapeHtml(category.label || "intel")).join(", ")
    : "";

  card.innerHTML = `
    <div class="card-header">
      <span class="card-source">${escapeHtml(item.source_type || "intel")}</span>
      <span class="card-status">${escapeHtml(categories || "active")}</span>
    </div>
    <h3 class="card-title">${escapeHtml(item.title || "Untitled")}</h3>
    <p class="card-desc">${escapeHtml(item.description || item.summary || "No description available.")}</p>
    <div class="card-chip-row">${metaChips || "<span class='card-chip'>Details <strong>Open full record</strong></span>"}</div>
    <div class="card-footer">
      <span>${escapeHtml(item.source || "Unknown source")}</span>
      <span>${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    </div>
  `;
  return card;
}

async function loadArticles(reset = false) {
  if (reset) {
    state.offset = 0;
    state.total = 0;
    $("cardsGrid").innerHTML = "";
  }

  const data = await apiFetch(buildFeedPath(PAGE_SIZE, state.offset));
  const items = data.items || [];
  const grid = $("cardsGrid");

  if (reset && items.length === 0) {
    $("emptyState").classList.remove("hidden");
    $("loadMoreWrap").classList.add("hidden");
    $("feedSummary").textContent = "0 results loaded";
    return;
  }

  $("emptyState").classList.add("hidden");
  items.forEach(item => {
    state.detailCache.set(item.aid, item);
    grid.appendChild(renderCard(item));
  });

  state.offset += items.length;
  state.total = data.total || state.offset;
  $("feedSummary").textContent = `${Math.min(state.offset, state.total)} of ${state.total} records loaded for ${humanViewName(state.activeTab)}`;
  $("loadMoreWrap").classList.toggle("hidden", state.offset >= state.total);
  setLastUpdated();
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

function renderFacts(item) {
  const facts = [
    ["Author", item.author || "Unavailable"],
    ["Source", item.source || "Unknown"],
    ["Country", (item.country_names || []).join(", ") || "Unmapped"],
    ["Network", item.network || "Unknown"],
    ["IPs", item.ip_addresses || "None"],
    ["Attacker", item.attacker || "Unknown"],
    ["Team", item.team || "Unknown"],
    ["Web Server", item.web_server || "Unknown"],
    ["Published", formatDate(item.date || item.scraped_at)],
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
  $("modalTopTag").textContent = item.top_tag || (item.country_names || []).join(", ") || "Live Record";
  $("modalTitle").textContent = item.title || "Untitled";
  $("modalMeta").innerHTML = `
    <span>AID: ${escapeHtml(item.aid || "")}</span>
    <span>Date: ${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    <span>Source URL: ${escapeHtml(item.url || item.seed_url || "Unavailable")}</span>
  `;

  renderFacts(item);
  $("modalSummary").textContent = item.description || item.summary || "No description available.";

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
  readButton.href = item.url || "#";
  readButton.style.pointerEvents = item.url ? "auto" : "none";
  readButton.style.opacity = item.url ? "1" : "0.55";

  $("modalJsonLink").href = `${getBase()}/feed/${encodeURIComponent(item.aid)}`;
  $("detailBackdrop").classList.remove("hidden");
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
    window.alert(`Failed to load detail: ${error.message}`);
  }
}

function closeDetailModal() {
  $("detailBackdrop").classList.add("hidden");
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

  $("pakdbStatus").textContent = "Searching PakDB...";
  $("pakdbHistoryList").innerHTML = "";

  try {
    const data = await apiFetch("/pakdb/lookup", false, {
      method: "POST",
      body: { number }
    });

    const items = data.items || [];
    $("pakdbStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No PakDB results found.";
    $("pakdbHistoryList").innerHTML = items.map(item => `
      <div class="compact-item">
        <div class="compact-title">${escapeHtml(item.name || "Unknown")}</div>
        <div class="compact-item-footer">
          <span class="compact-meta">CNIC: ${escapeHtml(item.cnic || "-")}</span>
          <span class="compact-meta">Mobile: ${escapeHtml(item.mobile || "-")}</span>
        </div>
        <div class="compact-meta">${escapeHtml(item.address || "")}</div>
      </div>
    `).join("");
  } catch (error) {
    $("pakdbStatus").textContent = error.message;
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
  updateHeader(target);
  setActiveNavigation(target);

  document.querySelectorAll(".view-panel").forEach(panel => panel.classList.add("hidden"));

  if (target === "homepage") {
    $("viewHomepage").classList.remove("hidden");
    await fetchStats();
    await initHeatmap();
    await fetchRecentIntel();
    return;
  }

  if (target === "admin-users") {
    $("viewAdminUsers").classList.remove("hidden");
    refreshUserList();
    return;
  }

  if (target === "pakdb") {
    $("viewPakdb").classList.remove("hidden");
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
      } else if (state.currentView !== "pakdb") {
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

  $("settingsBtn").addEventListener("click", () => {
    $("apiBaseInput").value = getBase();
    $("apiKeyInput").value = localStorage.getItem(STORAGE_KEY) || "";
    $("settingsBackdrop").classList.remove("hidden");
  });

  $("settingsClose").addEventListener("click", () => $("settingsBackdrop").classList.add("hidden"));
  $("settingsBackdrop").addEventListener("click", event => {
    if (event.target === $("settingsBackdrop")) $("settingsBackdrop").classList.add("hidden");
  });

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

  $("searchInput").addEventListener("input", debounce(() => {
    if (state.currentView !== "homepage" && state.currentView !== "admin-users" && state.currentView !== "pakdb") {
      loadArticles(true);
    }
  }, SEARCH_DEBOUNCE_MS));

  $("loadMoreBtn").addEventListener("click", () => loadArticles(false));
  $("pakdbSearchBtn").addEventListener("click", runPakdbLookup);
  $("pakdbInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runPakdbLookup();
  });
}

async function initApp() {
  setupEventListeners();
  if (!await checkAuth()) return;
  await checkHealth();
  await switchView("homepage");
  setLastUpdated();
  scheduleRefresh();
}

initApp().catch(error => {
  console.error(error);
});
