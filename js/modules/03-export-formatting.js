function buildExportDocumentHtml(payload, options = {}) {
  const autoPrint = options.autoPrint !== false;
  const metadata = Array.isArray(payload.metadata) ? payload.metadata : Object.entries(payload.metadata || {});
  const metadataRows = metadata.filter(([_, value]) => String(formatExportValue(value)).trim());
  const sectionsHtml = (payload.sections || []).map(section => renderExportSection(section)).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(payload.title || "DarkPulse Export")}</title>
  <style>
    :root {
      color-scheme: light;
    }
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      font-family: "Outfit", Arial, sans-serif;
      background: #edf2f7;
      color: #0f172a;
      padding: 32px;
    }
    .export-shell {
      max-width: 1040px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #dbe4ee;
      border-radius: 28px;
      padding: 32px;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.08);
    }
    .export-kicker {
      margin: 0 0 8px;
      color: #ff5a3d;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      font-size: 12px;
      font-weight: 800;
    }
    .export-shell h1 {
      margin: 0;
      font-size: 32px;
      line-height: 1.15;
    }
    .export-subtitle {
      margin: 10px 0 0;
      color: #475569;
      font-size: 15px;
      line-height: 1.6;
    }
    .export-meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0 0;
    }
    .export-meta-item,
    .export-field-item {
      border: 1px solid #e2e8f0;
      border-radius: 18px;
      padding: 14px 16px;
      background: #f8fafc;
    }
    .export-meta-label,
    .export-field-label {
      display: block;
      color: #64748b;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .export-meta-value,
    .export-field-value {
      display: block;
      color: #0f172a;
      font-size: 15px;
      line-height: 1.55;
      word-break: break-word;
    }
    .export-section {
      margin-top: 28px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
    }
    .export-print-note {
      margin: 18px 0 0;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid #dbe4ee;
      background: #f8fafc;
      color: #475569;
      font-size: 13px;
      line-height: 1.6;
    }
    .export-section h3 {
      margin: 0 0 14px;
      font-size: 18px;
    }
    .export-section-text,
    .export-card-text {
      color: #334155;
      line-height: 1.7;
      white-space: pre-wrap;
    }
    .export-list {
      margin: 0;
      padding-left: 20px;
      color: #334155;
      line-height: 1.7;
    }
    .export-image-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .export-image-card {
      margin: 0;
      border: 1px solid #dbe4ee;
      border-radius: 20px;
      overflow: hidden;
      background: #f8fafc;
      break-inside: avoid;
    }
    .export-image-card img {
      display: block;
      width: 100%;
      max-height: 360px;
      object-fit: cover;
      background: #e2e8f0;
    }
    .export-image-card figcaption {
      padding: 10px 14px;
      color: #475569;
      font-size: 12px;
      font-weight: 700;
    }
    .export-field-grid,
    .export-card-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
    }
    .export-card {
      border: 1px solid #dbe4ee;
      border-radius: 20px;
      padding: 18px;
      background: #fff;
      break-inside: avoid;
    }
    .export-card-head {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 12px;
    }
    .export-card h4 {
      margin: 0;
      font-size: 17px;
    }
    .export-card-head p {
      margin: 6px 0 0;
      color: #64748b;
      font-size: 13px;
    }
    .export-card-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
    }
    .export-card-tags span {
      border: 1px solid #dbe4ee;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 12px;
      color: #334155;
      background: #f8fafc;
    }
    .export-pre {
      margin: 0;
      padding: 18px;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 20px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      line-height: 1.6;
    }
    @media print {
      body {
        background: #fff;
        padding: 0;
      }
      .export-shell {
        max-width: none;
        border: none;
        border-radius: 0;
        box-shadow: none;
        padding: 0;
      }
      .export-section,
      .export-card,
      .export-meta-item,
      .export-field-item {
        break-inside: avoid;
      }
    }
  </style>
</head>
<body>
  <article class="export-shell">
    <p class="export-kicker">${escapeHtml(payload.kicker || "DarkPulse Export")}</p>
    <h1>${escapeHtml(payload.title || "DarkPulse Export")}</h1>
    ${payload.subtitle ? `<p class="export-subtitle">${escapeHtml(payload.subtitle)}</p>` : ""}
    ${metadataRows.length ? `
      <div class="export-meta">
        ${metadataRows.map(([label, value]) => `
          <div class="export-meta-item">
            <span class="export-meta-label">${escapeHtml(label)}</span>
            <span class="export-meta-value">${escapeHtml(formatExportValue(value))}</span>
          </div>
        `).join("")}
      </div>
    ` : ""}
    <div class="export-print-note">DarkPulse prepared this printable export for PDF saving. If the print dialog does not open automatically, use <strong>Ctrl+P</strong> or your browser Print action.</div>
    ${sectionsHtml}
  </article>
  ${autoPrint ? `
  <script>
    window.addEventListener("load", function () {
      var images = Array.prototype.slice.call(document.images || []);
      var waits = images.map(function (img) {
        if (img.complete) return Promise.resolve();
        return new Promise(function (resolve) {
          img.addEventListener("load", resolve, { once: true });
          img.addEventListener("error", resolve, { once: true });
        });
      });
      Promise.race([
        Promise.all(waits),
        new Promise(function (resolve) { setTimeout(resolve, 4200); })
      ]).then(function () {
        window.focus();
        window.print();
      });
    });
  </script>
  ` : ""}
</body>
</html>`;
}

function createPrintWindowShell() {
  const printWindow = window.open("", "_blank");
  if (!printWindow) return null;
  printWindow.document.write(`<!DOCTYPE html><html><head><title>Preparing PDF export</title></head><body style="font-family: Arial, sans-serif; padding: 24px; color: #0f172a; background: #f8fafc;">Preparing DarkPulse PDF export...</body></html>`);
  printWindow.document.close();
  return printWindow;
}

function exportPayloadAsJson(payload) {
  const fileBase = slugifyFilename(payload.filenameBase || payload.title || "darkpulse-export");
  triggerFileDownload(
    `${fileBase}-${formatExportTimestamp()}.json`,
    JSON.stringify(payload.data, null, 2),
    "application/json"
  );
}

function exportPayloadAsPdf(payload, printWindow = null) {
  const exportWindow = printWindow || createPrintWindowShell();
  if (!exportWindow) {
    throw new Error("Popup was blocked. Allow popups to save PDF exports.");
  }

  const html = buildExportDocumentHtml(payload, { autoPrint: true });
  const blob = new Blob([html], { type: "text/html" });
  const objectUrl = URL.createObjectURL(blob);
  exportWindow.location.replace(objectUrl);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
}

function updateHeader(viewName) {
  const meta = VIEW_META[viewName] || VIEW_META.all;
  $("viewTitle").textContent = meta.title;
  $("viewSubtitle").textContent = meta.subtitle;
}

function setLastUpdated() {
  const lastUpdated = $("lastUpdated");
  if (lastUpdated) {
    lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  }
}

function isSmartUpdateRunning(status) {
  return status === "queued" || status === "running" || status === "cancelling";
}

function syncSmartUpdateButton(isRunning = false) {
  const startButton = $("smartUpdateBtn");
  const stopButton = $("stopSmartUpdateBtn");
  const alertButton = $("alertSummaryBtn");
  const isCancelling = state.smartUpdateStatus === "cancelling";

  if (startButton) {
    if (!startButton.dataset.originalText || /scanning|stopping/i.test(startButton.dataset.originalText)) {
      startButton.dataset.originalText = startButton.textContent || "Scan Now";
    }
    startButton.classList.toggle("scanning", isRunning && !isCancelling);
    startButton.disabled = isRunning;
    startButton.textContent = isRunning
      ? (isCancelling ? "Stopping..." : "Scanning...")
      : "Scan Now";
  }

  if (stopButton) {
    stopButton.disabled = !isRunning || isCancelling;
    stopButton.textContent = isCancelling ? "Stopping..." : "Stop Scan";
  }

  if (alertButton) {
    const hasSummary = Boolean(
      state.smartUpdatePayload &&
      (state.smartUpdatePayload.active_run || state.smartUpdatePayload.latest_run || state.smartUpdatePayload.latest_notification)
    );
    alertButton.disabled = !hasSummary;
  }
}

function initSidebarAutomationCollapse() {
  const sidebar = document.querySelector(".app-sidebar");
  const nav = document.querySelector(".sidebar-nav");
  if (!sidebar || !nav || sidebar.dataset.automationScrollReady === "1") return;

  sidebar.dataset.automationScrollReady = "1";
  let lastScrollTop = nav.scrollTop;
  nav.addEventListener("scroll", () => {
    const currentScrollTop = nav.scrollTop;
    const delta = currentScrollTop - lastScrollTop;

    if (currentScrollTop <= 12 || delta < -8) {
      sidebar.classList.remove("sidebar-automation-collapsed");
    } else if (delta > 8 && currentScrollTop > 24) {
      sidebar.classList.add("sidebar-automation-collapsed");
    }

    lastScrollTop = currentScrollTop;
  }, { passive: true });
}

function formatSmartUpdateStatus(status) {
  switch (status) {
    case "running":
    case "queued":
      return "Automation Running";
    case "cancelling":
      return "Stopping Scan";
    case "completed":
      return "New Intel Synced";
    case "completed_no_new":
      return "No New Intel";
    case "completed_with_errors":
      return "Partial Source Error";
    case "cancelled":
      return "Scan Stopped";
    case "failed":
      return "Automation Failed";
    default:
      return "Automation Idle";
  }
}

function formatSourceProgressChip(item, active = false) {
  const label = item.label || SMART_UPDATE_SOURCE_LABELS[item.source] || item.source || "Source";
  const newRecords = Number(item.new_records || 0);
  const liveCount = item.current_count ?? item.after_count ?? item.before_count ?? 0;

  if (item.status === "failed") {
    return `${label} failed`;
  }
  if (item.status === "cancelled") {
    return `${label} stopped (+${newRecords})`;
  }
  if (item.status === "cancelling") {
    return `${label} stopping (+${newRecords})`;
  }
  if (active) {
    return `${label} +${newRecords} live (${liveCount})`;
  }
  return `${label} +${newRecords}`;
}

function buildAlertSummary(payload) {
  const activeRun = payload?.active_run;
  const latestRun = payload?.latest_run;
  const latestNotification = payload?.latest_notification;
  const run = activeRun || latestRun;
  const sourceResults = Array.isArray(run?.source_results)
    ? run.source_results
    : Array.isArray(latestNotification?.source_results)
      ? latestNotification.source_results
      : [];

  if (!run && sourceResults.length === 0) {
    return "No scan summary is available yet.";
  }

  const heading = activeRun && isSmartUpdateRunning(activeRun.status)
    ? "Live scan summary"
    : "Latest scan summary";
  const statusLine = `Status: ${formatSmartUpdateStatus(run?.status || latestNotification?.status || "idle")}`;
  const liveTotal = sourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0);
  const summaryTotal = activeRun && isSmartUpdateRunning(activeRun.status)
    ? liveTotal
    : (run?.new_records_total ?? latestNotification?.new_records_total ?? liveTotal);
  const totalLine = `New records: ${summaryTotal || 0}`;

  const lines = sourceResults.map(item => {
    const label = item.label || SMART_UPDATE_SOURCE_LABELS[item.source] || item.source || "Source";
    const newRecords = Number(item.new_records || 0);
    const total = item.current_count ?? item.after_count ?? item.before_count ?? 0;
    const sourceStatus = item.status || "idle";
    return `${label}: ${newRecords} new, total ${total}, status ${sourceStatus}`;
  });

  return [heading, statusLine, totalLine, "", ...lines].join("\n");
}

function buildAlertSummaryData(payload) {
  const activeRun = payload?.active_run;
  const latestRun = payload?.latest_run;
  const latestNotification = payload?.latest_notification;
  const run = activeRun || latestRun;
  const sourceResults = Array.isArray(run?.source_results)
    ? run.source_results
    : Array.isArray(latestNotification?.source_results)
      ? latestNotification.source_results
      : [];
  const status = run?.status || latestNotification?.status || "idle";
  const totalNew = activeRun && isSmartUpdateRunning(activeRun.status)
    ? sourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0)
    : Number(run?.new_records_total ?? latestNotification?.new_records_total ?? 0);

  return {
    heading: activeRun && isSmartUpdateRunning(activeRun.status) ? "Live Scan Summary" : "Latest Scan Summary",
    title: formatSmartUpdateStatus(status),
    status,
    triggeredBy: run?.triggered_by || latestNotification?.triggered_by || "operator",
    startedAt: run?.started_at || latestNotification?.started_at || "",
    completedAt: run?.completed_at || latestNotification?.completed_at || "",
    totalNew,
    sourceResults,
    channel: run?.delivery?.channel_label || latestNotification?.delivery?.channel_label || "Dashboard Alert",
    jobId: run?.job_id || latestNotification?.job_id || ""
  };
}

