/* ── CONFIG ─────────────────────────────────────────────────────── */
const API_BASE = localStorage.getItem('darkpulse_base') || 'http://localhost:8000';
const STORAGE_KEY = 'darkpulse_api_key';
const PAGE_SIZE = 100;
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
  'exploit': '#e11d48',
  'social': '#8b5cf6',
  'leak': '#f43f5e',
  'api': '#0ea5e9',
  'defacement': '#dc2626',
  'threat': '#f97316',
  'other': '#64748b',
};
function catColor(label) { return CAT_COLOR[label?.toLowerCase()] || '#64748b'; }

/* ── STATE ───────────────────────────────────────────────────────── */
let allArticles = [];    // news articles
let allThreats = [];     // exploit/social/leak/etc
let offset = 0;
let threatOffset = 0;
let totalItems = 0;
let totalThreats = 0;
let activeTab = 'all';   // all | news | exploit | social | leak | defacement
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
  const { aid, url, seed_url, title, author, date, scraped_at, top_tag, source_type, categories = [], entities = [], summary, description, source, network } = article;
  const displayTag = top_tag || source_type || '';
  const color = catColor(displayTag);
  const topCats = (Array.isArray(categories) ? categories : []).slice(0, 2);
  const entArr = Array.isArray(entities) ? entities : Object.entries(entities || {}).flatMap(([lbl, items]) => (items || []).map(i => ({ label: lbl, text: typeof i === 'string' ? i : i.text })));
  const orgPills = entArr.filter(e => e.label === 'ORG').slice(0, 4);
  const locPills = entArr.filter(e => e.label === 'LOC').slice(0, 3);
  const favicon = faviconUrl(seed_url || url);
  const domain = source || domainFrom(seed_url || url);
  const displayDate = date || scraped_at || '';

  // Network badge for dark web items
  const networkStr = typeof network === 'object' ? (network.name || network.type || 'Tor') : network;
  const networkBadge = networkStr && networkStr.toLowerCase() !== 'clearnet' ? `<span class="tag-badge" style="color:#e11d48;border-color:#e11d48;font-size:.65rem">🧅 ${networkStr}</span>` : '';

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
      <div style="display:flex;gap:.4rem;align-items:center">
        ${networkBadge}
        ${displayTag ? `<span class="tag-badge" style="color:${color};border-color:${color}">${displayTag}</span>` : ''}
      </div>
    </div>
    <div class="card-title">${title || '(no title)'}</div>
    ${(summary || description) ? `
      <div class="card-summary-wrap">
        <button class="ai-toggle" aria-expanded="false" aria-label="Toggle summary">⚡ Summary</button>
        <p class="card-summary">${summary || description}</p>
      </div>` : ''}
    <div class="card-meta">
      ${author ? `<span class="card-meta-item">✍ ${author}</span>` : ''}
      ${displayDate ? `<span class="card-meta-item">📅 ${formatDate(displayDate)}</span>` : ''}
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
  const { url, seed_url, title, author, date, top_tag, categories = [], summary, description } = article;
  const rawEntities = article.entities || {};
  const entArr = Array.isArray(rawEntities)
    ? rawEntities
    : Object.entries(rawEntities).flatMap(([lbl, items]) =>
        (items || []).map(i => ({ label: lbl, text: typeof i === 'string' ? i : i.text }))
      );
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
  entArr.forEach(e => { if (e && e.label) { (grouped[e.label] = grouped[e.label] || []).push(e); } });
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
async function updateStats(articles) {
  // Fetch stats from backend
  try {
    const stats = await apiFetch('/stats', true);
    statTotal.textContent = stats.total || articles.length;

    // Update tab counts
    const nc = document.getElementById('tabNewsCount');
    const ec = document.getElementById('tabExploitCount');
    const sc = document.getElementById('tabSocialCount');
    const lc = document.getElementById('tabLeakCount');
    const dc = document.getElementById('tabDefaceCount');
    const ac = document.getElementById('tabApiCount');
    if (nc) nc.textContent = stats.news ? `(${stats.news})` : '';
    if (ec) ec.textContent = stats.exploit ? `(${stats.exploit})` : '';
    if (sc) sc.textContent = stats.social ? `(${stats.social})` : '';
    if (lc) lc.textContent = stats.leak ? `(${stats.leak})` : '';
    if (dc) dc.textContent = stats.defacement ? `(${stats.defacement})` : '';
    if (ac) ac.textContent = stats.api ? `(${stats.api})` : '';
  } catch {
    statTotal.textContent = articles.length;
  }

  const today = new Date().toISOString().slice(0, 10);
  const todayCount = articles.filter(a => a.date === today || a.scraped_at === today).length;
  statToday.textContent = todayCount;

  // Count by category
  const counts = {};
  articles.forEach(a => {
    const tag = a.top_tag || a.source_type;
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
  articles.forEach(a => {
    const t = a.top_tag || a.source_type;
    if (t) catCounts[t] = (catCounts[t] || 0) + 1;
  });
  const maxCat = Math.max(1, ...Object.values(catCounts));
  categoryFilters.innerHTML = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([tag, n]) => {
      const pct = (n / maxCat) * 100;
      return `
      <label class="filter-item" style="position:relative; z-index:1;">
        <div style="position:absolute; left:0; top:0; bottom:0; width:${pct}%; background:${catColor(tag)}; opacity:0.15; border-radius:4px; z-index:-1; pointer-events:none;"></div>
        <div style="display:flex; align-items:center; gap:.5rem; width:100%;">
          <input type="checkbox" value="${tag}" ${activeFilters.categories.has(tag) ? 'checked' : ''} />
          <span class="filter-item-label" style="color:${catColor(tag)}; font-weight:600;">${tag}</span>
          <span class="filter-item-count">${n}</span>
        </div>
      </label>`;
    }).join('');

  categoryFilters.querySelectorAll('input').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) activeFilters.categories.add(cb.value);
      else activeFilters.categories.delete(cb.value);
      applyFilters();
    });
  });

  // Sources
  const srcCounts = {};
  articles.forEach(a => {
    const d = a.source || domainFrom(a.seed_url || a.url);
    if (d) srcCounts[d] = (srcCounts[d] || 0) + 1;
  });
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

  // Merge data based on active tab
  let pool;
  if (activeTab === 'all') {
    pool = [...allArticles, ...allThreats];
  } else if (activeTab === 'news') {
    pool = allArticles;
  } else {
    pool = allThreats.filter(t => t.source_type === activeTab);
  }

  const visible = pool.filter(a => {
    if (cats.size && !cats.has(a.top_tag) && !cats.has(a.source_type)) return false;
    if (srcs.size && !srcs.has(domainFrom(a.seed_url || a.url)) && !srcs.has(a.source)) return false;
    if (from && (a.date || a.scraped_at) && (a.date || a.scraped_at) < from) return false;
    if (to && (a.date || a.scraped_at) && (a.date || a.scraped_at) > to) return false;
    if (q) {
      const hay = ((a.title || '') + ' ' + (a.description || '') + ' ' + (a.summary || '') + ' ' + (a.source || '')).toLowerCase();
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
searchInput.addEventListener('keydown', async (e) => {
  if (e.key === 'Enter') {
    const q = searchInput.value.trim();
    if (!q) {
      activeFilters.search = '';
      applyFilters();
      return;
    }

    // Attempt NLQ if the query looks like a natural language sentence (e.g., more than 3 words)
    // Or just always use NLQ for the command palette
    activeFilters.search = q;
    
    // Show AI loading state
    cardsGrid.innerHTML = '';
    renderSkeletons(4);
    
    try {
      const res = await fetch(getBase() + '/search/nlq', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': getApiKey()
        },
        body: JSON.stringify({ query: q })
      });
      
      if (!res.ok) {
        // Fallback to local filter if NLQ endpoint fails
        applyFilters();
        return;
      }
      
      const data = await res.json();
      
      // Clear feed and show AI results
      cardsGrid.innerHTML = `<div style="grid-column: 1/-1; padding: 1rem; background: rgba(0, 212, 255, 0.1); border: 1px solid var(--cyan); border-radius: var(--radius); margin-bottom: 1rem; color: var(--cyan); box-shadow: 0 0 15px var(--cyan-glow);">
        <strong style="font-family: var(--mono); font-size: 1.1rem;">⚡ AI Analysis Complete</strong><br>
        <span style="font-size: 0.85rem; color: var(--text);">Found ${data.count} exact matches across the intelligence feed mapping to: "${q}"</span>
      </div>`;
      
      if (data.count === 0) {
        emptyState.classList.remove('hidden');
      } else {
        emptyState.classList.add('hidden');
        data.results.forEach((a, i) => {
          const c = buildCard(a);
          c.classList.add('new-item');
          c.style.animationDelay = `${i * 0.05}s`;
          cardsGrid.appendChild(c);
        });
      }
      
    } catch (err) {
      applyFilters(); // fallback
    }
  }
});
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
    threatOffset = 0;
    allArticles = [];
    allThreats = [];
    renderSkeletons();
  }

  try {
    // Fetch news + all threat types in parallel
    const threatTypes = ['exploit', 'social', 'leak', 'defacement', 'api'];
    const [newsData, ...threatResults] = await Promise.all([
      apiFetch(`/news?limit=${PAGE_SIZE}&offset=${offset}`),
      ...threatTypes.map(t =>
        apiFetch(`/threats?limit=${PAGE_SIZE}&offset=0&source_type=${t}`).catch(() => ({ total: 0, items: [] }))
      ),
    ]);

    totalItems = newsData.total || 0;
    const newsItems = newsData.items || [];
    const threatItems = threatResults.flatMap(r => r.items || []);
    totalThreats = threatItems.length;

    allArticles = reset ? newsItems : [...allArticles, ...newsItems];
    allThreats = reset ? threatItems : [...allThreats, ...threatItems];
    offset += newsItems.length;

    showFeed();
    const combined = [...allArticles, ...allThreats];
    buildSidebarFilters(combined);
    updateStats(combined);
    applyFilters();

    // Load more button
    const hasMoreNews = offset < totalItems;
    const hasMoreThreats = threatOffset < totalThreats;
    if (hasMoreNews || hasMoreThreats) {
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

/* ── TAB SWITCHING ────────────────────────────────────────────────── */
const pakdbPanel = $('pakdbPanel');
const githubPanel = $('githubPanel');
const apkPanel = $('apkPanel');
const pcgamePanel = $('pcgamePanel');
const collectorPanels = [pakdbPanel, githubPanel, apkPanel, pcgamePanel];

let _savedFeedDisplay = {};

function hideAllCollectorPanels() {
  collectorPanels.forEach(p => { if (p) p.classList.add('hidden'); });
}

function showCollectorPanel(panel, initFn) {
  const feedEls = [cardsGrid, lockScreen, errorScreen, emptyState, $('loadMoreWrap')];
  feedEls.forEach(el => {
    if (!el) return;
    _savedFeedDisplay[el.id] = el.classList.contains('hidden');
    el.classList.add('hidden');
  });
  hideAllCollectorPanels();
  panel.classList.remove('hidden');
  if (initFn) initFn();
}

function restoreFeedView() {
  hideAllCollectorPanels();
  const feedEls = [cardsGrid, lockScreen, errorScreen, emptyState, $('loadMoreWrap')];
  feedEls.forEach(el => {
    if (!el) return;
    if (_savedFeedDisplay[el.id] === false) el.classList.remove('hidden');
  });
  _savedFeedDisplay = {};
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTab = btn.dataset.tab;
    switch (activeTab) {
      case 'pakdb':   showCollectorPanel(pakdbPanel, pakdbInit); break;
      case 'github':  showCollectorPanel(githubPanel, githubInit); break;
      case 'apk':     showCollectorPanel(apkPanel, apkInit); break;
      case 'pcgame':  showCollectorPanel(pcgamePanel, pcgameInit); break;
      default:
        restoreFeedView();
        applyFilters();
    }
  });
});

/* ── PAKDB LOOKUP ─────────────────────────────────────────────────── */
let pakdbInitialized = false;

function pakdbInit() {
  if (pakdbInitialized) return;
  pakdbInitialized = true;

  const input = $('pakdbInput');
  const searchBtn = $('pakdbSearchBtn');
  const cnicInput = $('pakdbCnicInput');
  const cnicSearchBtn = $('pakdbCnicSearchBtn');
  const clearAllBtn = $('pakdbClearAllBtn');
  const status = $('pakdbStatus');
  const results = $('pakdbResults');
  const tbody = $('pakdbTableBody');
  const resultsTitle = $('pakdbResultsTitle');
  const historyList = $('pakdbHistoryList');

  // Load history on first visit
  pakdbLoadHistory(historyList);

  // ── Phone search ──
  async function doSearch() {
    let number = input.value.trim();
    if (!number) { input.focus(); return; }
    if (number.startsWith('3') && number.length === 10) number = '0' + number;

    searchBtn.disabled = true;
    searchBtn.innerHTML = '<span class="pakdb-spinner"></span> Searching…';
    status.classList.remove('hidden');
    status.className = 'pakdb-status pakdb-status-loading';
    status.innerHTML = '🔄 Connecting via Tor and scraping PakDB… This may take 30-120 seconds.';
    results.classList.add('hidden');

    try {
      const base = getBase();
      const res = await fetch(`${base}/pakdb/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ number }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      if (data.count === 0) {
        status.className = 'pakdb-status pakdb-status-warn';
        status.innerHTML = `⚠️ No records found for <strong>${data.query}</strong>`;
        results.classList.add('hidden');
      } else {
        status.className = 'pakdb-status pakdb-status-ok';
        status.innerHTML = `✅ Found <strong>${data.count}</strong> record(s) for <strong>${data.query}</strong>`;
        resultsTitle.textContent = `Results for ${data.query}`;
        tbody.innerHTML = buildResultRows(data.results);
        results.classList.remove('hidden');
      }
      pakdbLoadHistory(historyList);
    } catch (err) {
      status.className = 'pakdb-status pakdb-status-error';
      status.innerHTML = `❌ Lookup failed: ${esc(err.message)}`;
    } finally {
      searchBtn.disabled = false;
      searchBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Search';
    }
  }

  // ── CNIC / name search in history ──
  async function doCnicSearch() {
    const q = cnicInput.value.trim();
    if (!q) { cnicInput.focus(); return; }
    try {
      const base = getBase();
      const res = await fetch(`${base}/pakdb/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      if (!data.items || data.items.length === 0) {
        historyList.innerHTML = `<p class="pakdb-no-history">No matches found for "<strong>${esc(q)}</strong>"</p>`;
      } else {
        renderHistoryItems(historyList, data.items);
      }
    } catch {
      historyList.innerHTML = '<p class="pakdb-no-history">Search failed.</p>';
    }
  }

  // ── Clear all history ──
  async function doClearAll() {
    if (!confirm('Clear all PakDB lookup history?')) return;
    try {
      const base = getBase();
      await fetch(`${base}/pakdb/history`, { method: 'DELETE' });
      pakdbLoadHistory(historyList);
      status.classList.add('hidden');
      results.classList.add('hidden');
    } catch { /* ignore */ }
  }

  searchBtn.addEventListener('click', doSearch);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
  cnicSearchBtn.addEventListener('click', doCnicSearch);
  cnicInput.addEventListener('keydown', e => { if (e.key === 'Enter') doCnicSearch(); });
  clearAllBtn.addEventListener('click', doClearAll);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function buildResultRows(results) {
  return results.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><strong>${esc(r.name)}</strong></td>
      <td><code>${esc(r.cnic)}</code></td>
      <td>${esc(r.mobile)}</td>
      <td>${esc(r.address)}</td>
    </tr>
  `).join('');
}

function renderHistoryItems(container, items) {
  container.innerHTML = items.map(item => {
    const ts = item.timestamp ? new Date(item.timestamp).toLocaleString() : '';
    const hasResults = item.results && item.results.length > 0;
    const resultsTable = hasResults ? `
      <div class="pakdb-hist-detail hidden" data-detail="${item._id}">
        <table class="pakdb-table pakdb-table-compact">
          <thead><tr><th>#</th><th>Name</th><th>CNIC</th><th>Mobile</th><th>Address</th></tr></thead>
          <tbody>${buildResultRows(item.results)}</tbody>
        </table>
      </div>
    ` : '';
    return `
      <div class="pakdb-history-item" data-id="${item._id}">
        <div class="pakdb-hist-main" onclick="pakdbToggleDetail('${item._id}')">
          <div class="pakdb-history-query">
            <span class="pakdb-history-num">📞 ${esc(item.query)}</span>
            <span class="pakdb-history-count">${item.count} result(s)</span>
            ${hasResults ? '<span class="pakdb-expand-icon">▶</span>' : ''}
          </div>
          <div class="pakdb-hist-right">
            <span class="pakdb-history-time">${ts}</span>
            <button class="pakdb-delete-btn" onclick="event.stopPropagation();pakdbDeleteItem('${item._id}')" title="Delete">✕</button>
          </div>
        </div>
        ${resultsTable}
      </div>
    `;
  }).join('');
}

// Global functions for onclick
window.pakdbToggleDetail = function(id) {
  const detail = document.querySelector(`[data-detail="${id}"]`);
  const icon = document.querySelector(`[data-id="${id}"] .pakdb-expand-icon`);
  if (!detail) return;
  const open = !detail.classList.contains('hidden');
  detail.classList.toggle('hidden');
  if (icon) icon.textContent = open ? '▶' : '▼';
};

window.pakdbDeleteItem = async function(id) {
  try {
    const base = getBase();
    await fetch(`${base}/pakdb/history/${id}`, { method: 'DELETE' });
    const el = document.querySelector(`[data-id="${id}"]`);
    if (el) el.remove();
  } catch { /* ignore */ }
};

async function pakdbLoadHistory(container) {
  try {
    const base = getBase();
    const res = await fetch(`${base}/pakdb/history?limit=50`);
    const data = await res.json();
    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="pakdb-no-history">No lookup history yet.</p>';
      return;
    }
    renderHistoryItems(container, data.items);
  } catch {
    container.innerHTML = '<p class="pakdb-no-history">Could not load history.</p>';
  }
}

/* ── GITHUB TRIVY SCANNER ─────────────────────────────────────────── */
let githubInitialized = false;

function githubInit() {
  if (githubInitialized) return;
  githubInitialized = true;
  const base = getBase();

  $('githubScanBtn').addEventListener('click', async () => {
    const url = $('githubInput').value.trim();
    if (!url) return;
    const status = $('githubStatus');
    const results = $('githubResults');
    status.textContent = '🔄 Scanning repository with Trivy... This may take a few minutes.';
    status.className = 'pakdb-status';
    results.classList.add('hidden');

    try {
      const res = await fetch(`${base}/github/scan`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ repo_url: url })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Scan failed');

      status.textContent = `✅ Scan complete: ${data.count} findings`;
      status.className = 'pakdb-status pakdb-status-ok';

      // Render summary
      const s = data.summary || {};
      $('githubSummary').innerHTML = s.grade ? `
        <div class="github-grade-row">
          <span class="github-grade grade-${(s.grade || 'X')[0]}">${esc(s.grade)}</span>
          <span>Risk Score: <strong>${s.risk_score || '—'}</strong></span>
          <span>🔴 Critical: ${s.critical || 0}</span>
          <span>🟠 High: ${s.high || 0}</span>
          <span>🟡 Medium: ${s.medium || 0}</span>
          <span>🟢 Low: ${s.low || 0}</span>
          <span>🔑 Secrets: ${s.total_secrets || 0}</span>
        </div>` : '';

      // Render table
      $('githubResultsTitle').textContent = `${data.count} Finding(s)`;
      $('githubTableBody').innerHTML = (data.results || []).map((r, i) => `
        <tr>
          <td>${i + 1}</td>
          <td>${esc(r.name)}</td>
          <td>${esc(r.package_id)}</td>
          <td>${esc(r.version)}</td>
          <td>${esc(r.description).substring(0, 100)}</td>
        </tr>`).join('');
      results.classList.remove('hidden');

      githubLoadHistory($('githubHistoryList'));
    } catch (e) {
      status.textContent = `❌ ${e.message}`;
      status.className = 'pakdb-status pakdb-status-err';
    }
  });

  $('githubClearAllBtn').addEventListener('click', async () => {
    // Clear all by deleting each item
    const items = $('githubHistoryList').querySelectorAll('[data-id]');
    for (const el of items) {
      try { await fetch(`${base}/github/history/${el.dataset.id}`, { method: 'DELETE' }); } catch {}
    }
    githubLoadHistory($('githubHistoryList'));
  });

  githubLoadHistory($('githubHistoryList'));
}

async function githubLoadHistory(container) {
  try {
    const base = getBase();
    const res = await fetch(`${base}/github/history?limit=50`);
    const data = await res.json();
    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="pakdb-no-history">No scan history yet.</p>';
      return;
    }
    container.innerHTML = data.items.map(item => {
      const ts = item.timestamp ? new Date(item.timestamp).toLocaleString() : '';
      const s = item.summary || {};
      const grade = s.grade || '';
      return `
        <div class="pakdb-history-item" data-id="${item._id}">
          <div class="pakdb-hist-main" onclick="collectorToggleDetail('${item._id}')">
            <div class="pakdb-history-query">
              <span class="pakdb-history-num">🔗 ${esc(item.query)}</span>
              <span class="pakdb-history-count">${item.count} finding(s)</span>
              ${grade ? `<span class="github-grade-sm grade-${grade[0]}">${grade}</span>` : ''}
              ${item.count > 0 ? '<span class="pakdb-expand-icon">▶</span>' : ''}
            </div>
            <div class="pakdb-hist-right">
              <span class="pakdb-history-time">${ts}</span>
              <button class="pakdb-delete-btn" onclick="event.stopPropagation();collectorDeleteItem('github','${item._id}')" title="Delete">✕</button>
            </div>
          </div>
          ${item.results && item.results.length > 0 ? `
            <div class="pakdb-hist-detail hidden" data-detail="${item._id}">
              <table class="pakdb-table pakdb-table-compact">
                <thead><tr><th>#</th><th>Finding</th><th>Package</th><th>Version</th></tr></thead>
                <tbody>${item.results.slice(0, 20).map((r, i) => `<tr><td>${i+1}</td><td>${esc(r.name)}</td><td>${esc(r.package_id)}</td><td>${esc(r.version)}</td></tr>`).join('')}</tbody>
              </table>
            </div>` : ''}
        </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<p class="pakdb-no-history">Could not load history.</p>';
  }
}


/* ── APK MOD SCANNER ──────────────────────────────────────────────── */
let apkInitialized = false;

function apkInit() {
  if (apkInitialized) return;
  apkInitialized = true;
  const base = getBase();

  $('apkScanBtn').addEventListener('click', async () => {
    const url = $('apkInput').value.trim();
    if (!url) return;
    const status = $('apkStatus');
    const results = $('apkResults');
    status.textContent = '🔄 Scanning APK mirror sites... This may take a moment.';
    status.className = 'pakdb-status';
    results.classList.add('hidden');

    try {
      const res = await fetch(`${base}/apk/scan`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ playstore_url: url })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Scan failed');

      status.textContent = `✅ Scan complete: ${data.count} APK sources found`;
      status.className = 'pakdb-status pakdb-status-ok';

      $('apkResultsTitle').textContent = `${data.count} APK Source(s)`;
      $('apkTableBody').innerHTML = (data.results || []).map((r, i) => `
        <tr>
          <td>${i + 1}</td>
          <td>${esc(r.app_name)}</td>
          <td class="mono" style="font-size:.75rem">${esc(r.package_id)}</td>
          <td>${esc(r.version)}</td>
          <td>${esc(r.source)}</td>
          <td>${r.app_url ? `<a href="${esc(r.app_url)}" target="_blank" class="link-btn">Open ↗</a>` : '—'}</td>
        </tr>`).join('');
      results.classList.remove('hidden');

      apkLoadHistory($('apkHistoryList'));
    } catch (e) {
      status.textContent = `❌ ${e.message}`;
      status.className = 'pakdb-status pakdb-status-err';
    }
  });

  $('apkClearAllBtn').addEventListener('click', async () => {
    const items = $('apkHistoryList').querySelectorAll('[data-id]');
    for (const el of items) {
      try { await fetch(`${base}/apk/history/${el.dataset.id}`, { method: 'DELETE' }); } catch {}
    }
    apkLoadHistory($('apkHistoryList'));
  });

  apkLoadHistory($('apkHistoryList'));
}

async function apkLoadHistory(container) {
  try {
    const base = getBase();
    const res = await fetch(`${base}/apk/history?limit=50`);
    const data = await res.json();
    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="pakdb-no-history">No scan history yet.</p>';
      return;
    }
    container.innerHTML = data.items.map(item => {
      const ts = item.timestamp ? new Date(item.timestamp).toLocaleString() : '';
      // Show abbreviated query (just the app ID)
      const shortQ = item.query.includes('id=') ? item.query.split('id=')[1]?.split('&')[0] || item.query : item.query;
      return `
        <div class="pakdb-history-item" data-id="${item._id}">
          <div class="pakdb-hist-main" onclick="collectorToggleDetail('${item._id}')">
            <div class="pakdb-history-query">
              <span class="pakdb-history-num">📦 ${esc(shortQ)}</span>
              <span class="pakdb-history-count">${item.count} source(s)</span>
              ${item.count > 0 ? '<span class="pakdb-expand-icon">▶</span>' : ''}
            </div>
            <div class="pakdb-hist-right">
              <span class="pakdb-history-time">${ts}</span>
              <button class="pakdb-delete-btn" onclick="event.stopPropagation();collectorDeleteItem('apk','${item._id}')" title="Delete">✕</button>
            </div>
          </div>
          ${item.results && item.results.length > 0 ? `
            <div class="pakdb-hist-detail hidden" data-detail="${item._id}">
              <table class="pakdb-table pakdb-table-compact">
                <thead><tr><th>#</th><th>App</th><th>Version</th><th>Source</th></tr></thead>
                <tbody>${item.results.map((r, i) => `<tr><td>${i+1}</td><td>${esc(r.app_name)}</td><td>${esc(r.version)}</td><td>${esc(r.source)}</td></tr>`).join('')}</tbody>
              </table>
            </div>` : ''}
        </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<p class="pakdb-no-history">Could not load history.</p>';
  }
}


/* ── PC GAME SCANNER ──────────────────────────────────────────────── */
let pcgameInitialized = false;

function pcgameInit() {
  if (pcgameInitialized) return;
  pcgameInitialized = true;
  const base = getBase();

  $('pcgameScanBtn').addEventListener('click', async () => {
    const name = $('pcgameInput').value.trim();
    if (!name) return;
    const status = $('pcgameStatus');
    const results = $('pcgameResults');
    status.textContent = '🔄 Searching Steam and PCGamingWiki...';
    status.className = 'pakdb-status';
    results.classList.add('hidden');

    try {
      const res = await fetch(`${base}/pcgame/scan`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ game_name: name })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Scan failed');

      status.textContent = `✅ Search complete: ${data.count} results`;
      status.className = 'pakdb-status pakdb-status-ok';

      $('pcgameResultsTitle').textContent = `${data.count} Result(s) for "${esc(name)}"`;
      $('pcgameTableBody').innerHTML = (data.results || []).map((r, i) => `
        <tr>
          <td>${i + 1}</td>
          <td>${esc(r.name)}</td>
          <td>${esc(r.source)}</td>
          <td>${r.score || '—'}</td>
          <td>${r.pcgamingwiki ? `<a href="${esc(r.pcgamingwiki)}" target="_blank" class="link-btn">Wiki ↗</a>` : '—'}</td>
          <td>${r.url ? `<a href="${esc(r.url)}" target="_blank" class="link-btn">Open ↗</a>` : '—'}</td>
        </tr>`).join('');
      results.classList.remove('hidden');

      pcgameLoadHistory($('pcgameHistoryList'));
    } catch (e) {
      status.textContent = `❌ ${e.message}`;
      status.className = 'pakdb-status pakdb-status-err';
    }
  });

  $('pcgameClearAllBtn').addEventListener('click', async () => {
    const items = $('pcgameHistoryList').querySelectorAll('[data-id]');
    for (const el of items) {
      try { await fetch(`${base}/pcgame/history/${el.dataset.id}`, { method: 'DELETE' }); } catch {}
    }
    pcgameLoadHistory($('pcgameHistoryList'));
  });

  pcgameLoadHistory($('pcgameHistoryList'));
}

async function pcgameLoadHistory(container) {
  try {
    const base = getBase();
    const res = await fetch(`${base}/pcgame/history?limit=50`);
    const data = await res.json();
    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="pakdb-no-history">No scan history yet.</p>';
      return;
    }
    container.innerHTML = data.items.map(item => {
      const ts = item.timestamp ? new Date(item.timestamp).toLocaleString() : '';
      return `
        <div class="pakdb-history-item" data-id="${item._id}">
          <div class="pakdb-hist-main" onclick="collectorToggleDetail('${item._id}')">
            <div class="pakdb-history-query">
              <span class="pakdb-history-num">🎮 ${esc(item.query)}</span>
              <span class="pakdb-history-count">${item.count} result(s)</span>
              ${item.count > 0 ? '<span class="pakdb-expand-icon">▶</span>' : ''}
            </div>
            <div class="pakdb-hist-right">
              <span class="pakdb-history-time">${ts}</span>
              <button class="pakdb-delete-btn" onclick="event.stopPropagation();collectorDeleteItem('pcgame','${item._id}')" title="Delete">✕</button>
            </div>
          </div>
          ${item.results && item.results.length > 0 ? `
            <div class="pakdb-hist-detail hidden" data-detail="${item._id}">
              <table class="pakdb-table pakdb-table-compact">
                <thead><tr><th>#</th><th>Name</th><th>Source</th><th>Score</th></tr></thead>
                <tbody>${item.results.map((r, i) => `<tr><td>${i+1}</td><td>${esc(r.name)}</td><td>${esc(r.source)}</td><td>${r.score || '—'}</td></tr>`).join('')}</tbody>
              </table>
            </div>` : ''}
        </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<p class="pakdb-no-history">Could not load history.</p>';
  }
}

/* ── SHARED COLLECTOR HELPERS ──────────────────────────────────────── */
window.collectorToggleDetail = function(id) {
  const detail = document.querySelector(`[data-detail="${id}"]`);
  const icon = document.querySelector(`[data-id="${id}"] .pakdb-expand-icon`);
  if (!detail) return;
  const open = !detail.classList.contains('hidden');
  detail.classList.toggle('hidden');
  if (icon) icon.textContent = open ? '▶' : '▼';
};

window.collectorDeleteItem = async function(type, id) {
  try {
    const base = getBase();
    await fetch(`${base}/${type}/history/${id}`, { method: 'DELETE' });
    const el = document.querySelector(`[data-id="${id}"]`);
    if (el) el.remove();
  } catch { /* ignore */ }
};

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

/* ── WEBSOCKET LIVE FEED ──────────────────────────────────────────── */
let ws;
function connectWebSocket() {
  const key = getApiKey();
  const wsUrl = getBase().replace(/^http/, 'ws') + '/live-feed' + (key ? `?api_key=${encodeURIComponent(key)}` : '');
  ws = new WebSocket(wsUrl);
  
  ws.onmessage = (e) => {
    try {
      const article = JSON.parse(e.data);
      // Ensure we don't duplicate
      if (allThreats.some(t => t._id === article._id) || allArticles.some(a => a._id === article._id)) {
        return;
      }
      
      if (article.source_type === 'news') {
        allArticles.unshift(article);
        totalItems++;
      } else {
        allThreats.unshift(article);
        totalThreats++;
      }
      
      updateStats([...allArticles, ...allThreats]);
      
      // If it matches active filters/tab
      const visible = (activeTab === 'all' || activeTab === article.source_type) && !activeFilters.search;
      if (visible) {
        emptyState.classList.add('hidden');
        const card = buildCard(article);
        card.classList.add('new-item');
        cardsGrid.prepend(card);
      }
    } catch(err) {
      console.error('WS Error parsing message', err);
    }
  };
  
  ws.onclose = () => {
    console.log('WS disconnected. Reconnecting in 5s...');
    setTimeout(connectWebSocket, 5000);
  };
}

/* ── INIT ─────────────────────────────────────────────────────────── */
async function init() {
  await checkHealth();
  await loadArticles(true);
  connectWebSocket();
  scheduleRefresh();
}

init();
