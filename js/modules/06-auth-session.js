function _dpRenderSources(docs, container) {
  if (!docs || !docs.length) return;

  const sourcesEl = document.createElement("div");
  sourcesEl.className = "dp-msg-sources";
  sourcesEl.innerHTML = `<div class="dp-msg-sources-label">References (${docs.length})</div>`;

  docs.slice(0, 5).forEach((doc, i) => {
    const btn = document.createElement("button");
    btn.className = "dp-msg-source-chip";
    if (doc.aid) {
      btn.setAttribute("data-ai-source-aid", doc.aid);
    } else {
      btn.disabled = true;
    }
    btn.innerHTML = `
      <span class="dp-msg-source-num">${i + 1}</span>
      <span class="dp-msg-source-text">${escapeHtml(_dpSourceLabel(doc))}</span>
      <span class="dp-msg-source-arrow">${doc.aid ? "→" : ""}</span>
    `;
    if (doc.aid) {
      btn.addEventListener("click", () => {
        dpChatMinimize();
        showDetail(doc.aid);
      });
    }
    sourcesEl.appendChild(btn);
  });

  container.appendChild(sourcesEl);
}

function splitAiSectionLines(content = "", forceList = false) {
  const normalized = String(content || "")
    .replace(/\s+(?=\d+\.\s+)/g, "\n")
    .replace(/\s+-\s+/g, "\n")
    .trim();
  const lines = normalized
    .split(/\n+/)
    .map(line => line.replace(/^[-*•\d.)\s]+/, "").trim())
    .filter(Boolean);
  return forceList ? lines : (lines.length > 1 ? lines : [normalized]);
}

function _dpRenderStructuredAnswer(rawText, bubble) {
  // Clean and parse the structured sections
  const bodyText = sanitizeAiBranding(rawText)
    .replace(/\*\*\s*(Summary|Key Findings|Relevant Records|Missing Values)\s*:?\s*\*\*/g, "$1:")
    .replace(/^#+\s*(Summary|Key Findings|Relevant Records|Missing Values):?/gm, "$1:")
    .replace(/\s*(Summary|Key Findings|Relevant Records|Missing Values):\s*/g, "\n$1:\n")
    .replace(/\*\*/g, "")
    .trim();

  const sectionNames = ["Summary", "Key Findings", "Relevant Records", "Missing Values"];
  const sectionPattern = new RegExp(`^(${sectionNames.join("|")}):?\\s*`, "gm");
  const matches = [...bodyText.matchAll(sectionPattern)];

  if (!matches.length) {
    bubble.innerHTML = `<p style="margin:0">${escapeHtml(bodyText)}</p>`;
    return;
  }

  const sections = matches.map((match, index) => {
    const start = match.index + match[0].length;
    const end = matches[index + 1]?.index ?? bodyText.length;
    return { title: match[1], content: bodyText.slice(start, end).trim() };
  }).filter(s => s.content);

  bubble.innerHTML = sections.map(section => {
    const forceList = section.title !== "Summary";
    const lines = splitAiSectionLines(section.content, forceList);
    const markup = forceList || lines.length > 1
      ? `<ul>${lines.map(l => `<li>${escapeHtml(l)}</li>`).join("")}</ul>`
      : `<p>${escapeHtml(lines[0] || section.content)}</p>`;
    return `<section class="ai-chat-section"><h3>${escapeHtml(section.title)}</h3>${markup}</section>`;
  }).join("");
}

function _dpChatMetaLabel(metaInfo) {
  if (!metaInfo) return "response";
  const count = Number(metaInfo.count || 0);
  if (metaInfo.status === "general_chat") return "general chat";
  if (metaInfo.status === "empty") return "no matching records";
  if (metaInfo.status === "success") {
    return count === 1 ? "1 source record" : `top ${count} source records`;
  }
  return count === 1 ? "1 record" : `${count} records`;
}

async function runAiChatQuery() {
  const input = $("dpChatInput");
  const query = input.value.trim();
  if (!query || _dpChatBusy) return;

  _dpChatBusy = true;
  input.value = "";
  $("dpChatSendBtn").disabled = true;

  _dpAddUserMessage(query);
  _dpAddThinking();

  try {
    const headers = {
      "Content-Type": "application/json",
      Accept: "text/event-stream"
    };
    const token = getToken();
    const apiKey = localStorage.getItem(STORAGE_KEY) || "";
    if (token) headers.Authorization = `Bearer ${token}`;
    if (apiKey) headers["X-API-Key"] = apiKey;

    const response = await fetch(getBase() + "/api/ai/stream", {
      method: "POST",
      headers,
      body: JSON.stringify({ query, collection: "redis_kv_store", limit: 8, max_context_words: 1800 })
    });

    if (response.status === 401) { handleLogout(); throw new Error("Session expired"); }
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }

    _dpRemoveThinking();

    // Create AI message bubble
    const aiMsg = document.createElement("div");
    aiMsg.className = "dp-msg dp-msg-ai";
    const bubble = document.createElement("div");
    bubble.className = "dp-msg-bubble";
    const streamEl = document.createElement("div");
    streamEl.className = "dp-msg-stream";
    bubble.appendChild(streamEl);
    aiMsg.appendChild(bubble);
    $("dpChatMessages").appendChild(aiMsg);

    let fullAnswer = "";
    let metaDocs = [];
    let metaInfo = null;

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      sseBuffer += decoder.decode(value, { stream: true });
      const parts = sseBuffer.split("\n\n");
      sseBuffer = parts.pop() || "";

      for (const part of parts) {
        if (!part.trim()) continue;
        let eventType = "message", eventData = "";
        for (const line of part.split("\n")) {
          if (line.startsWith("event: ")) eventType = line.slice(7).trim();
          else if (line.startsWith("data: ")) eventData = line.slice(6);
        }

        if (eventType === "meta") {
          try {
            const meta = JSON.parse(eventData);
            metaInfo = meta;
            if (meta.status === "error" || meta.status === "empty") {
              streamEl.textContent = meta.message || "No data found.";
              break;
            }
            metaDocs = meta.documents || [];
          } catch(_) {}
        } else if (eventType === "chunk") {
          try {
            const text = JSON.parse(eventData);
            fullAnswer += text;
    streamEl.textContent = sanitizeAiBranding(fullAnswer);
            _dpScrollToBottom();
          } catch(_) {}
        } else if (eventType === "done") {
          break;
        }
      }
    }

    // Final structured render
    if (fullAnswer.trim()) {
      streamEl.remove();
      _dpRenderStructuredAnswer(sanitizeAiBranding(fullAnswer), bubble);
    }

    // Add source references
    if (metaDocs.length > 0) {
      _dpRenderSources(metaDocs, bubble);
    }

    // Add timestamp
    const now = new Date();
    const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const meta = document.createElement("div");
    meta.className = "dp-msg-meta";
    meta.innerHTML = `<span class="dp-msg-meta-dot"></span> ${time} · ${escapeHtml(_dpChatMetaLabel(metaInfo))}`;
    aiMsg.appendChild(meta);

    _dpScrollToBottom();

  } catch (error) {
    _dpRemoveThinking();
    const errMsg = document.createElement("div");
    errMsg.className = "dp-msg dp-msg-ai";
    errMsg.innerHTML = `<div class="dp-msg-bubble" style="border-color:rgba(255,80,80,0.3)">Warning: ${escapeHtml(sanitizeAiBranding(error.message))}</div>`;
    $("dpChatMessages").appendChild(errMsg);
    _dpScrollToBottom();
  } finally {
    _dpChatBusy = false;
    $("dpChatSendBtn").disabled = false;
    $("dpChatInput").focus();
  }
}

// Legacy aliases — keep these so old code referencing them doesn't crash
function openAiChatModal() { dpChatShow(); }
function closeAiChatModal() { dpChatMinimize(); }
function clearAiChat() { dpChatClear(); }

async function applyFeedFilters(options = {}) {
  const closeModal = options.closeModal !== false;
  const startDate = $("feedFilterStartDate").value.trim();
  const endDate = $("feedFilterEndDate").value.trim();
  const network = $("feedFilterNetwork").value.trim();
  const topic = $("feedFilterTopic").value.trim();

  if (startDate && endDate && startDate > endDate) {
    $("feedFilterStatus").textContent = "Start date cannot be later than end date.";
    return;
  }

  state.feedFilters = { startDate, endDate, network, topic };
  renderFeedFilterState();
  if (closeModal) closeFeedFiltersModal();

  if (!TOOL_VIEWS.includes(state.currentView) && state.currentView !== "homepage") {
    await loadArticles(true, 1);
  }
}

async function resetFeedFilters() {
  state.feedFilters = { startDate: "", endDate: "", network: "", topic: "" };
  $("feedFilterStartDate").value = "";
  $("feedFilterEndDate").value = "";
  $("feedFilterNetwork").value = "";
  $("feedFilterTopic").value = "";
  renderFeedFilterState();

  if (!TOOL_VIEWS.includes(state.currentView) && state.currentView !== "homepage") {
    await loadArticles(true, 1);
  }
}

function buildFeedPath(limit = PAGE_SIZE, page = state.feedPage || 1, includeRaw = false) {
  return buildFeedRequestPath({
    limit,
    page,
    includeRaw,
    sourceType: currentSourceType(),
    query: $("searchInput").value.trim(),
    filters: getActiveFeedFilters()
  });
}

function buildFeedRequestPath({
  limit = PAGE_SIZE,
  page = 1,
  includeRaw = false,
  sourceType = currentSourceType(),
  query = "",
  filters = getBlankFeedFilters()
} = {}) {
  const safePage = Math.max(1, Number(page) || 1);
  const safeFilters = normalizeFeedFilters(filters);
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String((safePage - 1) * limit)
  });

  if (sourceType && sourceType !== "all") params.set("source_type", sourceType);
  if (query) params.set("q", query);
  if (safeFilters.startDate) params.set("start_date", safeFilters.startDate);
  if (safeFilters.endDate) params.set("end_date", safeFilters.endDate);
  if (safeFilters.network) params.set("network", safeFilters.network);
  if (safeFilters.topic) params.set("topic", safeFilters.topic);
  if (includeRaw) params.set("include_raw", "true");

  return `/feed?${params.toString()}`;
}

function isFeedSnapshotFresh(snapshot) {
  return Boolean(
    snapshot &&
    typeof snapshot.cachedAt === "number" &&
    (Date.now() - snapshot.cachedAt) < FEED_SNAPSHOT_TTL_MS &&
    Array.isArray(snapshot.items)
  );
}

function storeFeedSnapshot(sourceType, query, filters, page, items, total) {
  const snapshotKey = buildFeedSnapshotKeyFor(sourceType, query, filters, page);
  state.feedSnapshots.set(snapshotKey, {
    cachedAt: Date.now(),
    items: Array.isArray(items) ? items.slice() : [],
    total: Number(total || 0)
  });
}

async function prefetchFeedSnapshot(viewName, page = 1) {
  const sourceType = TAB_SOURCE_MAP[viewName] || viewName || "all";
  const filters = getBlankFeedFilters();
  const snapshotKey = buildFeedSnapshotKeyFor(sourceType, "", filters, page);
  const existing = state.feedSnapshots.get(snapshotKey);
  if (isFeedSnapshotFresh(existing)) {
    return existing;
  }
  if (state.feedPrefetchPromises.has(snapshotKey)) {
    return state.feedPrefetchPromises.get(snapshotKey);
  }

  const promise = (async () => {
    try {
      const data = await apiFetch(buildFeedRequestPath({
        sourceType,
        page,
        limit: PAGE_SIZE,
        query: "",
        filters
      }));
      const items = Array.isArray(data.items) ? data.items : [];
      storeFeedSnapshot(sourceType, "", filters, page, items, data.total || items.length);
      items.forEach(item => {
        state.detailCache.set(item.aid, item);
      });
      return data;
    } catch (error) {
      console.error(`Feed prefetch failed for ${viewName}`, error);
      return null;
    } finally {
      state.feedPrefetchPromises.delete(snapshotKey);
    }
  })();

  state.feedPrefetchPromises.set(snapshotKey, promise);
  return promise;
}

function warmFeedSnapshots(force = false) {
  if (!getToken()) return Promise.resolve();
  if (state.feedWarmupPromise && !force) {
    return state.feedWarmupPromise;
  }

  const promise = (async () => {
    for (const viewName of FEED_PREFETCH_VIEWS) {
      if (!getToken()) break;
      await prefetchFeedSnapshot(viewName, 1);
      await new Promise(resolve => setTimeout(resolve, FEED_PREFETCH_DELAY_MS));
    }
  })();

  state.feedWarmupPromise = promise;
  promise.finally(() => {
    if (state.feedWarmupPromise === promise) {
      state.feedWarmupPromise = null;
    }
  });
  return promise;
}

function renderSearchInsight() {
  const bar = $("searchInsight");
  if (!bar) return;

  const query = $("searchInput").value.trim();
  if (state.currentView === "homepage" || TOOL_VIEWS.includes(state.currentView) || !query || query.length < MIN_GLOBAL_SEARCH_LENGTH) {
    bar.classList.add("hidden");
    $("searchInsightMeta").innerHTML = "";
    return;
  }

  const insight = state.semanticSearch;
  const title = $("searchInsightTitle");
  const message = $("searchInsightMessage");
  const meta = $("searchInsightMeta");

  bar.classList.remove("hidden");

  if (!insight || String(insight.query || "").toLowerCase() !== query.toLowerCase() || insight.pending) {
    title.textContent = `Analyzing "${query}"`;
    message.textContent = "DarkPulse is checking the restored feeds, entities, and summaries to find the best route for this query.";
    meta.innerHTML = `<span class="search-chip loading">Semantic route pending</span>`;
    return;
  }

  if (!insight.total) {
    title.textContent = `No results for "${query}"`;
    message.textContent = "No matching intelligence was found in the local restored records for this search. Try another actor, topic, domain, or keyword.";
    meta.innerHTML = `<span class="search-chip muted">0 matches</span>`;
    return;
  }

  const routeLabel = humanViewName(insight.suggested_view || "all");
  title.textContent = `${insight.total} matches for "${query}"`;
  message.textContent = `DarkPulse routed this query toward ${routeLabel} based on semantic matches across restored titles, descriptions, entities, actors, IPs, and related source text.`;
  meta.innerHTML = Object.entries(insight.source_counts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([source, count]) => `<span class="search-chip">${escapeHtml(humanViewName(source))} <strong>${escapeHtml(String(count))}</strong></span>`)
    .join("");
}

async function fetchSemanticGuide(query) {
  const cleanQuery = String(query || "").trim();
  if (!cleanQuery || cleanQuery.length < MIN_GLOBAL_SEARCH_LENGTH) {
    state.semanticSearch = null;
    renderSearchInsight();
    return null;
  }

  const cacheKey = cleanQuery.toLowerCase();
  const cached = state.semanticGuideCache.get(cacheKey);
  if (cached && (Date.now() - cached.cachedAt) < SEMANTIC_CACHE_TTL_MS) {
    state.semanticSearch = cached.data;
    renderSearchInsight();
    return cached.data;
  }

  state.semanticSearch = {
    query: cleanQuery,
    pending: true,
    total: 0,
    source_counts: {},
    suggested_view: "all"
  };
  renderSearchInsight();

  const data = await apiFetch(`/search/semantic?q=${encodeURIComponent(cleanQuery)}&limit=8`);
  state.semanticSearch = data;
  state.semanticGuideCache.set(cacheKey, {
    cachedAt: Date.now(),
    data
  });
  renderSearchInsight();
  return data;
}

