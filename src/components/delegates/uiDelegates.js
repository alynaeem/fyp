export function attachUIDelegates({ $, handlePaginationChange, handleExportAction } = {}) {
  document.addEventListener("click", async event => {
    const button = event.target.closest("[data-pagination-target]");
    if (!button) return;
    event.preventDefault();
    if (button.disabled) return;
    await handlePaginationChange(button.dataset.paginationTarget || "", button.dataset.paginationPage || "1");
  });

  document.addEventListener("click", async event => {
    const button = event.target.closest("[data-export-target]");
    if (!button) return;
    event.preventDefault();
    if (button.disabled) return;
    await handleExportAction(button.dataset.exportTarget || "", button.dataset.exportFormat || "json", button);
  });
}
