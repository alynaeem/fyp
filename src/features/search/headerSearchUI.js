export function createHeaderSearchUIModule({ state, $ } = {}) {
  function setHeaderSearchBusy(isBusy, label = "Searching local intelligence...") {
    state.headerSearchBusy = isBusy;
    const bar = $("headerSearchBar");
    const status = $("searchBarStatus");
    const icon = $("headerSearchIcon");

    if (bar) {
      bar.classList.toggle("is-busy", isBusy);
      bar.setAttribute("aria-busy", isBusy ? "true" : "false");
    }
    if (status) {
      status.textContent = label;
      status.classList.toggle("hidden", !isBusy);
    }
    if (icon) {
      icon.textContent = isBusy ? "..." : "/";
    }
  }

  return { setHeaderSearchBusy };
}
