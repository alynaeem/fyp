export function createHeaderSearchModule({
  state,
  $,
  renderSearchInsight,
  setHeaderSearchBusy,
  loadArticles,
  routeHomepageSearch,
  fetchSemanticGuide,
  switchView,
  showToast,
  TOOL_VIEWS,
  MIN_GLOBAL_SEARCH_LENGTH
} = {}) {
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

  return { handleHeaderSearch };
}

export function attachHeaderSearchHandlers({
  $,
  debounce,
  handleHeaderSearch,
  state,
  TOOL_VIEWS,
  SEARCH_DEBOUNCE_MS
} = {}) {
  $("searchInput").addEventListener("input", debounce(() => {
    const query = $("searchInput").value.trim();
    if (!query) {
      handleHeaderSearch(false);
      return;
    }
    if (state.currentView === "homepage" || state.currentView === "docs") return;
    if (!TOOL_VIEWS.includes(state.currentView)) {
      handleHeaderSearch(false);
    }
  }, SEARCH_DEBOUNCE_MS));

  $("searchInput").addEventListener("keydown", event => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    handleHeaderSearch(true);
  });
}

