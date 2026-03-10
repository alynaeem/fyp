/* ── CONFIG ─────────────────────────────────────────────────────── */
const API_BASE = localStorage.getItem('darkpulse_base') || 'http://localhost:8000';
const STORAGE_KEY = 'darkpulse_api_key';
const PAGE_SIZE = 50;
const REFRESH_MS = 5 * 60 * 1000; // 5 minutes

/* ── CATEGORY COLOURS ────────────────────────────────────────────── */
const CAT_COLOR = {
  'ransomware': '#ff4444',
  'malware': '#f97316',
  'phishing': '#a855f7',
  'vulnerability': '#f59e0b',
  'data breach': '#ef4444',
  'exposure': '#ec4899',
  'policy': '#3b82f6',
  'research': '#10b981',
  'scam': '#6366f1',
  'other': '#64748b',
};
function catColor(label) { return CAT_COLOR[label?.toLowerCase()] || '#64748b'; }

/* ── STATE ───────────────────────────────────────────────────────── */
let allArticles = [];
let offset = 0;
let totalItems = 0;
let activeFilters = { categories: new Set(), sources: new Set(), search: '', dateFrom: '', dateTo: '' };
let refreshTimer = null;

/* ── DOM REFS ────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const cardsGrid = $('cardsGrid');
const lockScreen = $('lockScreen');
const errorScreen = $('errorScreen');
const errorTitle = $('errorTitle');
const errorSub = $('errorSub');
const loadMoreBtn = $('loadMoreBtn');
const loadMoreWrap = $('loadMoreWrap');
const emptyState = $('emptyState');
const statTotal = $('statTotal');
const statToday = $('statToday');
const statTags = $('statTags');
const statusDot = $('statusDot');
const statusText = $('statusText');
const lastUpdated = $('lastUpdated');
const settingsBtn = $('settingsBtn');
const settingsBackdrop = $('settingsBackdrop');
const detailBackdrop = $('detailBackdrop');
const searchInput = $('searchInput');
const dateFrom = $('dateFrom');
const dateTo = $('dateTo');
const categoryFilters = $('categoryFilters');
const sourceFilters = $('sourceFilters');
const clearFilters = $('clearFilters');
const sidebarToggle = $('sidebarToggle');
const sidebarBody = $('sidebarBody');
const apiKeyInput = $('apiKeyInput');
const apiBaseInput = $('apiBaseInput');
const testResult = $('testResult');

/* ── API HELPERS ─────────────────────────────────────────────────── */
function getApiKey() { return localStorage.getItem(STORAGE_KEY) || ''; }
function getBase() { return localStorage.getItem('darkpulse_base') || 'http://localhost:8000'; }

async function apiFetch(path, noAuth = false) {
  const headers = { 'Accept': 'application/json' };
  const key = getApiKey();
  if (!noAuth && key) headers['X-API-Key'] = key;
  const res = await fetch(getBase() + path, { headers });
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status });
  return res.json();
}

/* ── HEALTH CHECK ────────────────────────────────────────────────── */
async function checkHealth() {
  try {
    const data = await apiFetch('/health', true);
    const ok = data.status === 'ok';
    statusDot.className = 'status-dot ' + (ok ? 'ok' : 'error');
    statusText.textContent = ok ? 'Connected' : 'Redis Unavailable';
  } catch {
    statusDot.className = 'status-dot error';
    statusText.textContent = 'Offline';
  }
}

/* ── SKELETON ────────────────────────────────────────────────────── */
function renderSkeletons(n = 6) {
  cardsGrid.innerHTML = Array.from({ length: n }, () => `
    <div class="skeleton-card" aria-hidden="true">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="skel skel-sm" style="width:110px"></div>
        <div class="skel skel-sm" style="width:70px"></div>
      </div>
      <div class="skel skel-lg" style="width:90%"></div>
      <div class="skel skel-md" style="width:75%"></div>
      <div class="skel skel-sm" style="width:55%"></div>
    </div>
  `).join('');
}

/* ── CARD RENDER ─────────────────────────────────────────────────── */
function domainFrom(url) {
  try { return new URL(url).hostname.replace('www.', ''); } catch { return url || '—'; }
}
function faviconUrl(url) {
  try { const u = new URL(url); return `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=32`; } catch { return ''; }
}
function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(iso));
  } catch { return iso; }
}

function buildCard(article) {
  const { aid, url, seed_url, title, author, date, top_tag, categories = [], entities = [], summary, description } = article;
  const color = catColor(top_tag);
  const topCats = categories.slice(0, 2);
  const orgPills = entities.filter(e => e.label === 'ORG').slice(0, 4);
  const locPills = entities.filter(e => e.label === 'LOC').slice(0, 3);
  const favicon = faviconUrl(seed_url || url);
  const domain = domainFrom(seed_url || url);

  const barsHtml = topCats.map(c => `
    <div class="conf-row">
      <span class="conf-label">${c.label}</span>
      <div class="conf-track"><div class="conf-fill" style="width:${Math.round(c.score * 100)}%;background:${catColor(c.label)}"></div></div>
      <span class="conf-pct">${Math.round(c.score * 100)}%</span>
    </div>`).join('');

  const pillsHtml = [
    ...orgPills.map(e => `<span class="pill pill-ORG">${e.text}</span>`),
    ...locPills.map(e => `<span class="pill pill-LOC">${e.text}</span>`),
  ].join('');

  const card = document.createElement('div');
  card.className = 'card';
  card.setAttribute('role', 'article');
  card.setAttribute('aria-label', title);
  card.dataset.aid = aid;
  card.innerHTML = `
    <div class="card-header">
      <div class="card-source">
        ${favicon ? `<img class="source-favicon" src="${favicon}" alt="" loading="lazy" onerror="this.style.display='none'">` : ''}
        <span class="source-domain mono">${domain}</span>
      </div>
      ${top_tag ? `<span class="tag-badge" style="color:${color};border-color:${color}">${top_tag}</span>` : ''}
    </div>
    <div class="card-title">${title || '(no title)'}</div>
    ${(summary || description) ? `
      <div class="card-summary-wrap">
        <button class="ai-toggle" aria-expanded="false" aria-label="Toggle AI summary">⚡ AI Summary</button>
        <p class="card-summary">${summary || description}</p>
      </div>` : ''}
    <div class="card-meta">
      ${author ? `<span class="card-meta-item">✍ ${author}</span>` : ''}
      ${date ? `<span class="card-meta-item">📅 ${formatDate(date)}</span>` : ''}
    </div>
    ${pillsHtml ? `<div class="entity-pills">${pillsHtml}</div>` : ''}
    ${barsHtml ? `<div class="conf-bars">${barsHtml}</div>` : ''}
  `;

  // AI toggle
  const toggle = card.querySelector('.ai-toggle');
  const summaryEl = card.querySelector('.card-summary');
  if (toggle && summaryEl) {
    toggle.addEventListener('click', e => {
      e.stopPropagation();
      const open = summaryEl.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open);
    });
  }

  // Open modal
  card.addEventListener('click', () => openDetailModal(article));
  return card;
}

/* ── DETAIL MODAL ────────────────────────────────────────────────── */
function openDetailModal(article) {
  const { url, seed_url, title, author, date, top_tag, categories = [], entities = [], summary, description } = article;
  const color = catColor(top_tag);
  const domain = domainFrom(seed_url || url);
  const favicon = faviconUrl(seed_url || url);

  $('modalSource').innerHTML = `
    ${favicon ? `<img class="source-favicon" src="${favicon}" alt="" onerror="this.style.display='none'">` : ''}
    <span>${domain}</span>`;
  $('modalTopTag').innerHTML = top_tag
    ? `<span class="tag-badge" style="color:${color};border-color:${color};font-size:.78rem">${top_tag}</span>` : '';
  $('modalTitle').textContent = title || '(no title)';
  $('modalMeta').innerHTML = [
    author && `<span>✍ ${author}</span>`,
    date && `<span>📅 ${formatDate(date)}</span>`,
  ].filter(Boolean).join('');
  $('modalSummary').textContent = summary || description || '(no summary available)';
  $('modalReadBtn').href = url || '#';

  // Entities grouped
  const grouped = {};
  entities.forEach(e => { (grouped[e.label] = grouped[e.label] || []).push(e); });
  const entityLabels = { ORG: 'Organizations', PER: 'People', LOC: 'Locations', MISC: 'Misc' };
  $('modalEntities').innerHTML = Object.entries(grouped).map(([lbl, items]) => `
    <div>
      <div class="entity-group-label">${entityLabels[lbl] || lbl}</div>
      <div class="entity-pills">${items.slice(0, 12).map(e => `<span class="pill pill-${lbl}">${e.text}</span>`).join('')}</div>
    </div>`).join('');

  // Categories
  $('modalCategories').innerHTML = categories.map(c => `
    <div class="conf-row" style="margin-bottom:.4rem">
      <span class="conf-label">${c.label}</span>
      <div class="conf-track"><div class="conf-fill" style="width:${Math.round(c.score * 100)}%;background:${catColor(c.label)}"></div></div>
      <span class="conf-pct">${Math.round(c.score * 100)}%</span>
    </div>`).join('');

  detailBackdrop.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}
function closeDetailModal() {
  detailBackdrop.classList.add('hidden');
  document.body.style.overflow = '';
}
$('detailClose').addEventListener('click', closeDetailModal);
detailBackdrop.addEventListener('click', e => { if (e.target === detailBackdrop) closeDetailModal(); });

/* ── SETTINGS MODAL ──────────────────────────────────────────────── */
function openSettings() {
  apiKeyInput.value = getApiKey();
  apiBaseInput.value = getBase();
  testResult.className = 'test-result';
  testResult.textContent = '';
  settingsBackdrop.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  apiKeyInput.focus();
}
function closeSettings() {
  settingsBackdrop.classList.add('hidden');
  document.body.style.overflow = '';
}
settingsBtn.addEventListener('click', openSettings);
$('lockSettingsBtn').addEventListener('click', openSettings);
$('settingsClose').addEventListener('click', closeSettings);
settingsBackdrop.addEventListener('click', e => { if (e.target === settingsBackdrop) closeSettings(); });

$('testConnBtn').addEventListener('click', async () => {
  const key = apiKeyInput.value.trim();
  const base = apiBaseInput.value.trim() || 'http://localhost:8000';
  testResult.className = 'test-result';
  testResult.textContent = 'Testing…';
  try {
    const res = await fetch(`${base}/news?limit=1`, { headers: { 'X-API-Key': key, 'Accept': 'application/json' } });
    if (res.ok) {
      testResult.className = 'test-result ok';
      testResult.textContent = '✓ Connection successful';
    } else if (res.status === 403) {
      testResult.className = 'test-result err';
      testResult.textContent = '✗ Invalid API key (403 Forbidden)';
    } else {
      testResult.className = 'test-result err';
      testResult.textContent = `✗ Server returned ${res.status}`;
    }
  } catch (err) {
    testResult.className = 'test-result err';
    testResult.textContent = `✗ Cannot reach ${base}`;
  }
});

$('saveSettingsBtn').addEventListener('click', () => {
  const key = apiKeyInput.value.trim();
  const base = apiBaseInput.value.trim() || 'http://localhost:8000';
  localStorage.setItem(STORAGE_KEY, key);
  localStorage.setItem('darkpulse_base', base);
  closeSettings();
  init();
});

/* ── STATS BAR ───────────────────────────────────────────────────── */
function updateStats(articles) {
  const today = new Date().toISOString().slice(0, 10);
  const todayCount = articles.filter(a => a.date === today).length;
  statTotal.textContent = totalItems || articles.length;
  statToday.textContent = todayCount;

  // Count by category
  const counts = {};
  articles.forEach(a => {
    const tag = a.top_tag;
    if (tag) counts[tag] = (counts[tag] || 0) + 1;
  });
  statTags.innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([tag, n]) => `
      <span class="stat-tag">
        <span class="stat-tag-dot" style="background:${catColor(tag)}"></span>
        ${tag} <strong>${n}</strong>
      </span>`).join('');
}

/* ── FILTERS ─────────────────────────────────────────────────────── */
function buildSidebarFilters(articles) {
  // Categories
  const catCounts = {};
  articles.forEach(a => { const t = a.top_tag; if (t) catCounts[t] = (catCounts[t] || 0) + 1; });
  categoryFilters.innerHTML = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([tag, n]) => `
      <label class="filter-item">
        <input type="checkbox" value="${tag}" ${activeFilters.categories.has(tag) ? 'checked' : ''} />
        <span class="filter-item-label" style="color:${catColor(tag)}">${tag}</span>
        <span class="filter-item-count">${n}</span>
      </label>`).join('');

  categoryFilters.querySelectorAll('input').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) activeFilters.categories.add(cb.value);
      else activeFilters.categories.delete(cb.value);
      applyFilters();
    });
  });

  // Sources
  const srcCounts = {};
  articles.forEach(a => { const d = domainFrom(a.seed_url || a.url); if (d) srcCounts[d] = (srcCounts[d] || 0) + 1; });
  sourceFilters.innerHTML = Object.entries(srcCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([src, n]) => `
      <label class="filter-item">
        <input type="checkbox" value="${src}" ${activeFilters.sources.has(src) ? 'checked' : ''} />
        <span class="filter-item-label mono" style="font-size:.78rem">${src}</span>
        <span class="filter-item-count">${n}</span>
      </label>`).join('');

  sourceFilters.querySelectorAll('input').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) activeFilters.sources.add(cb.value);
      else activeFilters.sources.delete(cb.value);
      applyFilters();
    });
  });
}

function applyFilters() {
  const q = activeFilters.search.toLowerCase();
  const cats = activeFilters.categories;
  const srcs = activeFilters.sources;
  const from = activeFilters.dateFrom;
  const to = activeFilters.dateTo;

  const visible = allArticles.filter(a => {
    if (cats.size && !cats.has(a.top_tag)) return false;
    if (srcs.size && !srcs.has(domainFrom(a.seed_url || a.url))) return false;
    if (from && a.date && a.date < from) return false;
    if (to && a.date && a.date > to) return false;
    if (q) {
      const hay = ((a.title || '') + ' ' + (a.description || '') + ' ' + (a.summary || '')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  cardsGrid.innerHTML = '';
  if (visible.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
    visible.forEach(a => cardsGrid.appendChild(buildCard(a)));
  }
}

/* ── FILTER EVENTS ───────────────────────────────────────────────── */
searchInput.addEventListener('input', () => { activeFilters.search = searchInput.value; applyFilters(); });
dateFrom.addEventListener('change', () => { activeFilters.dateFrom = dateFrom.value; applyFilters(); });
dateTo.addEventListener('change', () => { activeFilters.dateTo = dateTo.value; applyFilters(); });
clearFilters.addEventListener('click', () => {
  activeFilters = { categories: new Set(), sources: new Set(), search: '', dateFrom: '', dateTo: '' };
  searchInput.value = '';
  dateFrom.value = '';
  dateTo.value = '';
  buildSidebarFilters(allArticles);
  applyFilters();
});

/* ── SIDEBAR TOGGLE (mobile) ─────────────────────────────────────── */
sidebarToggle.addEventListener('click', () => {
  sidebarBody.classList.toggle('open');
});

/* ── SHOW / HIDE SCREENS ──────────────────────────────────────────── */
function showFeed() {
  lockScreen.classList.add('hidden');
  errorScreen.classList.add('hidden');
  cardsGrid.classList.remove('hidden');
}
function showLock() {
  lockScreen.classList.remove('hidden');
  errorScreen.classList.add('hidden');
  cardsGrid.classList.add('hidden');
  loadMoreBtn.classList.add('hidden');
  emptyState.classList.add('hidden');
}
function showError(title, sub) {
  errorTitle.textContent = title;
  errorSub.textContent = sub;
  errorScreen.classList.remove('hidden');
  lockScreen.classList.add('hidden');
  cardsGrid.classList.add('hidden');
  loadMoreBtn.classList.add('hidden');
  emptyState.classList.add('hidden');
}

/* ── LOAD ARTICLES ───────────────────────────────────────────────── */
async function loadArticles(reset = false) {
  if (reset) {
    offset = 0;
    allArticles = [];
    renderSkeletons();
  }

  try {
    const data = await apiFetch(`/news?limit=${PAGE_SIZE}&offset=${offset}`);
    totalItems = data.total || 0;
    const items = data.items || [];
    allArticles = reset ? items : [...allArticles, ...items];
    offset += items.length;

    showFeed();
    buildSidebarFilters(allArticles);
    updateStats(allArticles);
    applyFilters();

    // Load more button
    if (offset < totalItems) {
      loadMoreBtn.classList.remove('hidden');
    } else {
      loadMoreBtn.classList.add('hidden');
    }

    lastUpdated.textContent = 'Updated ' + new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit' }).format(new Date());

  } catch (err) {
    if (err.status === 403) {
      showLock();
    } else if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
      showError('Cannot reach backend', `Check that the API is running at ${getBase()}.`);
    } else {
      showError('Something went wrong', err.message);
    }
  }
}

/* ── LOAD MORE ────────────────────────────────────────────────────── */
loadMoreBtn.addEventListener('click', () => loadArticles(false));
$('retryBtn').addEventListener('click', () => loadArticles(true));

/* ── AUTO REFRESH ─────────────────────────────────────────────────── */
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => { loadArticles(true); scheduleRefresh(); }, REFRESH_MS);
}

/* ── KEYBOARD ─────────────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeDetailModal();
    closeSettings();
  }
});

/* ── INIT ─────────────────────────────────────────────────────────── */
async function init() {
  await checkHealth();
  await loadArticles(true);
  scheduleRefresh();
}

init();
