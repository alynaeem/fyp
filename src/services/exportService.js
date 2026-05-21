import { escapeHtml, formatExportTimestamp, formatExportValue, slugifyFilename } from "../utils/index.js";

export function renderExportFields(fields) {
  const rows = (Array.isArray(fields) ? fields : Object.entries(fields || {}))
    .filter(([_, value]) => String(formatExportValue(value)).trim() && String(formatExportValue(value)).trim() !== "-");

  if (!rows.length) return "";

  return `
    <div class="export-field-grid">
      ${rows.map(([label, value]) => `
        <div class="export-field-item">
          <span class="export-field-label">${escapeHtml(label)}</span>
          <span class="export-field-value">${escapeHtml(formatExportValue(value))}</span>
        </div>
      `).join("")}
    </div>
  `;
}

export function renderExportCards(cards = []) {
  if (!Array.isArray(cards) || !cards.length) return "";

  return `
    <div class="export-card-grid">
      ${cards.map(card => `
        <article class="export-card">
          <div class="export-card-head">
            <div>
              <h4>${escapeHtml(card.title || "Record")}</h4>
              ${card.subtitle ? `<p>${escapeHtml(card.subtitle)}</p>` : ""}
            </div>
            ${Array.isArray(card.tags) && card.tags.length ? `
              <div class="export-card-tags">
                ${card.tags.map(tag => `<span>${escapeHtml(tag)}</span>`).join("")}
              </div>
            ` : ""}
          </div>
          ${card.text ? `<p class="export-card-text">${escapeHtml(card.text)}</p>` : ""}
          ${renderExportFields(card.fields)}
        </article>
      `).join("")}
    </div>
  `;
}

export function renderExportSection(section) {
  if (!section) return "";

  let body = "";
  if (section.text) {
    body += `<p class="export-section-text">${escapeHtml(section.text)}</p>`;
  }
  if (section.list && section.list.length) {
    body += `<ul class="export-list">${section.list.map(item => `<li>${escapeHtml(formatExportValue(item))}</li>`).join("")}</ul>`;
  }
  if (section.fields) {
    body += renderExportFields(section.fields);
  }
  if (section.cards) {
    body += renderExportCards(section.cards);
  }
  if (section.pre) {
    body += `<pre class="export-pre">${escapeHtml(section.pre)}</pre>`;
  }

  if (!body) return "";

  return `
    <section class="export-section">
      <h3>${escapeHtml(section.title || "Section")}</h3>
      ${body}
    </section>
  `;
}

export function buildExportDocumentHtml(payload, options = {}) {
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
    .export-card-text,
    .export-pre {
      color: #334155;
      font-size: 14px;
      line-height: 1.65;
    }
    .export-pre {
      white-space: pre-wrap;
      background: #0f172a;
      color: #f8fafc;
      padding: 16px;
      border-radius: 16px;
      overflow: auto;
    }
    .export-list {
      margin: 0;
      padding-left: 20px;
      color: #334155;
    }
    .export-card-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }
    .export-card {
      border: 1px solid #e2e8f0;
      border-radius: 20px;
      padding: 18px;
      background: #f8fafc;
      break-inside: avoid;
    }
    .export-card-head {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 12px;
    }
    .export-card-head h4 {
      margin: 0;
      font-size: 16px;
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
      display: inline-flex;
      align-items: center;
      padding: 5px 10px;
      border-radius: 999px;
      background: rgba(255, 90, 61, 0.12);
      color: #c2412d;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    @media print {
      body {
        background: #ffffff;
        padding: 0;
      }
      .export-shell {
        border: none;
        border-radius: 0;
        box-shadow: none;
        padding: 0;
      }
      .export-print-note {
        display: none;
      }
    }
  </style>
</head>
<body>
  <article class="export-shell">
    ${payload.kicker ? `<p class="export-kicker">${escapeHtml(payload.kicker)}</p>` : ""}
    <h1>${escapeHtml(payload.title || "Export")}</h1>
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
      setTimeout(function () {
        window.focus();
        window.print();
      }, 280);
    });
  </script>
  ` : ""}
</body>
</html>`;
}

export function createPrintWindowShell() {
  const printWindow = window.open("", "_blank");
  if (!printWindow) return null;
  printWindow.document.write(`<!DOCTYPE html><html><head><title>Preparing PDF export</title></head><body style="font-family: Arial, sans-serif; padding: 24px; color: #0f172a; background: #f8fafc;">Preparing DarkPulse PDF export...</body></html>`);
  printWindow.document.close();
  return printWindow;
}

export function exportPayloadAsJson(payload) {
  const fileBase = slugifyFilename(payload.filenameBase || payload.title || "darkpulse-export");
  const blob = new Blob([JSON.stringify(payload.data, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = `${fileBase}-${formatExportTimestamp()}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

export function exportPayloadAsPdf(payload, printWindow = null) {
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
