function buildPlaystoreExportPayload() {
  const entry = state.scanExports.playstore || { query: "", items: [] };
  const items = Array.isArray(entry.items) ? entry.items : [];
  if (!items.length) throw new Error("Run a Playstore scan before exporting.");

  return {
    filenameBase: `playstore-scan-${entry.query || "results"}`,
    kicker: "DarkPulse Scan Export",
    title: "Playstore Scanner",
    subtitle: `Query: ${entry.query || "-"}`,
    metadata: [
      ["Query", entry.query || "-"],
      ["Results", items.length],
      ["Exported", formatDate(new Date().toISOString())]
    ],
    sections: [
      {
        title: "Result Set",
        cards: items.map(item => ({
          title: item.app_name || "Unknown Application",
          subtitle: item.source || item.network || "clearnet",
          text: normalizePreviewText((item.description || "").trim() || "Description not available from the source page.", "Description not available from the source page."),
          fields: [
            ["Package", item.package_id || "N/A"],
            ["Updated", item.latest_date || "N/A"],
            ["Size", item.apk_size || "N/A"],
            ["Type", item.content_type || "apk"],
            ["Publisher", item.publisher || "N/A"],
            ["Network", item.network || "clearnet"],
            ["Version", item.version || "Unknown Version"],
            ["Download Link", item.download_link || "-"],
            ["Page URL", item.url || "-"]
          ]
        }))
      }
    ],
    data: {
      query: entry.query || "",
      count: items.length,
      results: items
    }
  };
}

function buildSoftwareExportPayload() {
  const entry = state.scanExports.software || { query: "", items: [] };
  const items = Array.isArray(entry.items) ? entry.items : [];
  if (!items.length) throw new Error("Run a PC game scan before exporting.");

  return {
    filenameBase: `pc-game-scan-${entry.query || "results"}`,
    kicker: "DarkPulse Scan Export",
    title: "PC Game Scan",
    subtitle: `Query: ${entry.query || "-"}`,
    metadata: [
      ["Query", entry.query || "-"],
      ["Results", items.length],
      ["Exported", formatDate(new Date().toISOString())]
    ],
    sections: [
      {
        title: "Result Set",
        cards: items.map(item => ({
          title: item.app_name || item.name || "Software result",
          subtitle: item.network || "clearnet",
          text: item.mod_features || "No additional feature notes.",
          fields: [
            ["Package Id", item.package_id || "-"],
            ["App URL", item.app_url || item.url || "-"],
            ["Version", item.version || "-"],
            ["Content Type", item.content_type || "pc_game"],
            ["Download Link", item.download_link || "-"],
            ["Size", item.apk_size || "-"],
            ["Latest Date", item.latest_date || "-"]
          ]
        }))
      }
    ],
    data: {
      query: entry.query || "",
      count: items.length,
      results: items
    }
  };
}

function buildSeoExportPayload() {
  const data = state.scanExports.seo;
  if (!data) throw new Error("Run an SEO scan before exporting.");

  const audits = Object.keys(data.audits || {}).map(key => data.audits[key]);
  const aiSuggestions = String(data.ai_suggestions || "")
    .split(/\n+/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => line.replace(/^[-*•]\s*/, "").replace(/^\d+[.)]\s*/, "").trim())
    .filter(Boolean);

  return {
    filenameBase: `seo-report-${data.url || "report"}`,
    kicker: "DarkPulse Scan Export",
    title: "SEO Analysis Report",
    subtitle: data.url || "Website posture report",
    metadata: [
      ["Target URL", data.url || "-"],
      ["Host", (() => { try { return new URL(data.url).hostname; } catch { return "-"; } })()],
      ["SEO Health Grade", data.seoHealthGrade || data.grade || "-"],
      ["Scan Confidence", data.scanConfidenceGrade || "-"],
      ["Scan Mode", data.scanModeUsed || "-"],
      ["Raw Scan Available", data.rawScanAvailable ? "Yes" : "No"],
      ["Rendered Scan Available", data.renderedScanAvailable ? "Yes" : "No"],
      ["Findings", audits.length],
      ["Scanned On", data.timestamp || "-"]
    ],
    sections: [
      data.crawlerVisibility ? {
        title: "Crawler Visibility",
        text: data.crawlerVisibility.reason || "",
        fields: [
          ["Level", data.crawlerVisibility.level || "-"],
          ["Raw Body Text", data.crawlerVisibility.signals?.bodyTextLength ?? "-"],
          ["Raw Scripts", data.crawlerVisibility.signals?.scriptCount ?? "-"],
          ["Rendered Body Text", data.crawlerVisibility.signals?.renderedBodyTextLength ?? "-"],
          ["JS Heavy Likely", data.crawlerVisibility.signals?.jsHeavyLikely ? "Yes" : "No"],
          ["Access Limited", data.crawlerVisibility.signals?.accessLimitedSignals ? "Yes" : "No"],
          ["Bot Protection Likely", data.crawlerVisibility.signals?.botProtectionLikely ? "Yes" : "No"]
        ]
      } : null,
      data.ai_message || aiSuggestions.length ? {
        title: "Recommendations",
        text: data.ai_message || "",
        list: aiSuggestions
      } : null,
      {
        title: "Audit Findings",
        cards: audits.map((audit, index) => ({
          title: audit.title || `Audit ${index + 1}`,
          subtitle: `Score ${audit.score ?? "-"} | ${audit.status || "-"}`,
          text: [audit.description, audit.note].filter(Boolean).join(" "),
          fields: [
            ["Audit Id", audit.id || index + 1],
            ["Confidence", audit.confidence || "-"],
            ["Evidence Source", audit.evidenceSource || "-"],
            ["Evidence", audit.evidence || "-"],
            ["Recommendation", audit.recommendation || "-"]
          ]
        }))
      }
    ].filter(Boolean),
    data
  };
}

function buildRepoExportPayload() {
  const data = state.scanExports.repo;
  if (!data) throw new Error("Run a repository scan before exporting.");

  const summary = data.summary || {};
  const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities.map(item => ({ ...item, finding_type: "Vulnerability" })) : [];
  const secrets = Array.isArray(data.secrets) ? data.secrets.map(item => ({ ...item, finding_type: "Secret" })) : [];
  const misconfigs = Array.isArray(data.misconfigs) ? data.misconfigs.map(item => ({ ...item, finding_type: "Misconfiguration" })) : [];
  const findings = [...misconfigs, ...secrets, ...vulnerabilities];

  return {
    filenameBase: `repository-scan-${data.query || summary.repo_name || "report"}`,
    kicker: "DarkPulse Scan Export",
    title: "Repository Scan Report",
    subtitle: data.query || summary.repo_name || "Repository posture summary",
    metadata: [
      ["Target URL", data.query || "-"],
      ["Host", summary.host || "github.com"],
      ["Grade", summary.grade || "-"],
      ["Risk Score", summary.risk_score ?? 0],
      ["Findings", findings.length],
      ["Scanned By", summary.scanned_by || "DarkPulse / Trivy"]
    ],
    sections: [
      Array.isArray(summary.recommendations) && summary.recommendations.length
        ? { title: "Recommendations", list: summary.recommendations }
        : null,
      {
        title: "Findings",
        cards: findings.map((finding, index) => ({
          title: finding.title || `Finding ${index + 1}`,
          subtitle: `${finding.finding_type || "Finding"} • ${finding.severity || "UNKNOWN"}`,
          text: finding.description || finding.snippet || "",
          fields: [
            ["ID", finding.id || "-"],
            ["Severity", finding.severity || "UNKNOWN"],
            ["Confidence", finding.confidence || "-"],
            ["Snippet", finding.snippet || "-"]
          ]
        }))
      }
    ].filter(Boolean),
    data
  };
}

async function resolveExportPayload(target) {
  switch (target) {
    case "detail":
      if (!state.currentDetailItem) throw new Error("Open an article before exporting.");
      return buildDetailExportPayload(state.currentDetailItem);
    case "pakdb":
      return buildPakdbExportPayload();
    case "credential":
      return buildCredentialExportPayload();
    case "confidential":
      return buildConfidentialExportPayload();
    case "playstore":
      return buildPlaystoreExportPayload();
    case "software":
      return buildSoftwareExportPayload();
    case "seo":
      return buildSeoExportPayload();
    case "repo":
      return buildRepoExportPayload();
    default:
      throw new Error("Unsupported export target.");
  }
}

async function handleExportAction(target, format, button) {
  const normalizedFormat = format === "pdf" ? "pdf" : "json";
  const printWindow = normalizedFormat === "pdf" ? createPrintWindowShell() : null;
  setInlineButtonBusy(button, true, normalizedFormat === "pdf" ? "Preparing PDF..." : "Preparing JSON...");

  try {
    const payload = await resolveExportPayload(target);
    if (normalizedFormat === "pdf") {
      exportPayloadAsPdf(payload, printWindow);
      showToast("PDF export opened. Use your browser's save-to-PDF option.", "success");
    } else {
      exportPayloadAsJson(payload);
      showToast("JSON export downloaded.", "success");
    }
  } catch (error) {
    if (printWindow && !printWindow.closed) {
      printWindow.close();
    }
    showToast(error.message || "Export failed.", "error");
  } finally {
    setInlineButtonBusy(button, false, normalizedFormat === "pdf" ? "Preparing PDF..." : "Preparing JSON...");
  }
}

function closeAlertSummaryModal() {
  $("alertSummaryBackdrop").classList.add("hidden");
}

function renderPakdbResultCard(item) {
  return `
    <article class="identity-card">
      <div class="identity-header">
        <div>
          <h3 class="identity-name">${escapeHtml(normalizePreviewText(item.name || "Unknown Record", "Unknown Record"))}</h3>
          <p class="identity-address">${escapeHtml(normalizePreviewText(item.address || "Address unavailable", "Address unavailable"))}</p>
        </div>
        <span class="identity-pill">National Identity</span>
      </div>
      <div class="identity-grid">
        <div class="identity-field">
          <span class="identity-field-label">CNIC</span>
          <span class="identity-field-value">${escapeHtml(item.cnic || "-")}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">Mobile</span>
          <span class="identity-field-value">${escapeHtml(item.mobile || "-")}</span>
        </div>
      </div>
      <div class="identity-meta-line">Matched from the connected national identity lookup backend.</div>
    </article>
  `;
}

function formatHealingStatus(status) {
  const normalized = String(status || "unknown").toLowerCase();
  switch (normalized) {
    case "checking":
      return "Checking";
    case "healthy":
      return "Healthy";
    case "blocked":
      return "Blocked";
    case "failed":
      return "Failed";
    case "repaired":
      return "Repaired";
    case "no_data":
      return "No Data";
    case "target_unreachable":
    case "unreachable":
      return "Unreachable";
    case "html_changed":
    case "changed":
      return "HTML Changed";
    case "repair_ready":
    case "auto_fixed":
      return "Repair Ready";
    case "needs_review":
      return "Needs Review";
    case "skipped":
      return "Skipped";
    case "error":
      return "Error";
    case "discovered":
      return "Discovered";
    default:
      return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
  }
}

function cleanHealingMessage(value = "") {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  if (/BrowserType\.launch: Executable doesn't exist|playwright install|headless_shell/i.test(text)) {
    return "Playwright browser is not installed. Run: playwright install";
  }
  if (/cloudflare|cf-ray|checking your browser|access denied|forbidden|blocked/i.test(text)) {
    return "Target is reachable but appears blocked by Cloudflare or an access-control page.";
  }
  if (/timeout|timed out/i.test(text)) {
    return "Target check timed out. Re-test later or verify network/proxy access.";
  }
  if (text.length > 260) {
    return `${text.slice(0, 257)}...`;
  }
  return text;
}

function healingIssueType(item = {}) {
  const blob = [
    item.status,
    item.live_status,
    item.last_event_message,
    item.message,
    item.skip_reason,
    item.last_error,
    item.target_url,
    item.target_domain,
  ].map(value => String(value || "").toLowerCase()).join(" ");

  if (!item.target_url && !item.target_domain) return "no_url";
  if (/playwright|headless_shell|browser executable|chromium/i.test(blob)) return "playwright";
  if (/cloudflare|blocked|access denied|forbidden/i.test(blob)) return "blocked";
  if (/timeout|timed out/i.test(blob)) return "timeout";
  if (/selector|no match|failed selector/i.test(blob)) return "selector";
  return "";
}

function healingPrimaryStatus(item = {}) {
  const rawStatus = String(item.status || "discovered").toLowerCase();
  const liveStatus = String(item.live_status || "").toLowerCase();
  const issue = healingIssueType(item);

  if (state.healingMonitor.checkModal.scriptId === (item.script_id || item.target_key || "") && state.healingMonitor.checkModal.outcome === "running") {
    return "checking";
  }
  if (issue === "playwright" || rawStatus === "error") return "failed";
  if (issue === "blocked" || liveStatus === "blocked") return "blocked";
  if (rawStatus === "auto_fixed") return "repaired";
  if (rawStatus === "target_unreachable" || rawStatus === "unreachable") return "failed";
  if (rawStatus === "html_changed" || rawStatus === "changed") return "html_changed";
  if (rawStatus === "repair_ready") return "repair_ready";
  if (rawStatus === "no_data") return "needs_review";
  if (rawStatus === "skipped") return "skipped";
  if (rawStatus === "healthy") return "healthy";
  if (rawStatus === "needs_review") return "needs_review";
  return rawStatus || "discovered";
}

function healingSecondaryBadges(item = {}) {
  const badges = [];
  const issue = healingIssueType(item);
  const live = String(item.live_status || "not_checked").toLowerCase();
  const drift = String(item.html_change_status || "not_checked").toLowerCase();
  const selectorScore = item.selector_health_score;

  if (!item.target_url && !item.target_domain) badges.push(["No URL", "no_url"]);
  if (live && live !== "not_checked") badges.push([formatHealingLiveStatus(live), live]);
  if (issue === "playwright") badges.push(["Playwright Missing", "playwright"]);
  if (issue === "blocked") badges.push(["Cloudflare / Blocked", "blocked"]);
  if (issue === "timeout") badges.push(["Timeout", "timeout"]);
  if (selectorScore !== null && selectorScore !== undefined && Number(selectorScore) < 100) {
    badges.push(["Selector Failed", "selector"]);
  }
  if (drift && drift !== "not_checked" && drift !== "no_change") {
    badges.push([formatHealingDriftStatus(drift), drift]);
  }
  return badges.slice(0, 4);
}

function renderHealingPill(status) {
  const normalized = String(status || "unknown").toLowerCase();
  return `<span class="healing-status-pill status-${escapeHtml(normalized)}">${escapeHtml(formatHealingStatus(normalized))}</span>`;
}

function renderHealingPrimaryPill(item = {}) {
  return renderHealingPill(healingPrimaryStatus(item));
}

function formatHealingLiveStatus(status) {
  const normalized = String(status || "not_checked").toLowerCase();
  switch (normalized) {
    case "live":
      return "Live";
    case "redirect":
      return "Redirect";
    case "blocked":
      return "Blocked";
    case "server_error":
      return "Server Error";
    case "client_error":
      return "Client Error";
    case "timeout":
      return "Timeout";
    case "dns_failure":
      return "DNS Failure";
    case "connection_error":
      return "Connection Error";
    case "not_checked":
      return "Not Checked";
    default:
      return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
  }
}

function formatHealingDriftStatus(status) {
  const normalized = String(status || "not_checked").toLowerCase();
  switch (normalized) {
    case "no_change":
      return "No Change";
    case "minor_change":
      return "Minor Change";
    case "major_change":
      return "Major Change";
    case "not_checked":
      return "Not Checked";
    default:
      return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
  }
}

function renderHealingMetric(value, suffix = "") {
  if (value === null || value === undefined || value === "") {
    return "n/a";
  }
  return `${escapeHtml(String(value))}${suffix}`;
}

function renderHealingSuggestions(suggestions = []) {
  if (!Array.isArray(suggestions) || !suggestions.length) {
    return `<div class="healing-empty-copy">No selector repair suggestions were needed in the latest check.</div>`;
  }
  return `
    <ul class="healing-suggestion-list">
      ${suggestions.slice(0, 5).map(item => `
        <li>
          <strong>${escapeHtml(item.old_selector || "selector")}</strong>
          <span> -> ${escapeHtml(item.suggested_selector || item.new_selector || "manual review")}</span>
        </li>
      `).join("")}
    </ul>
  `;
}

