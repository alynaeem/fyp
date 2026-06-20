function renderRepoReport(data) {
  const summary = data.summary || {};
  const grade = String(summary.grade || "A").toUpperCase();
  const isDanger = grade === "F" || grade === "E";
  const container = $("repoScanReport");
  const totalFindings = (data.misconfigs?.length || 0) + (data.secrets?.length || 0) + (data.vulnerabilities?.length || 0);
  const postureLabel = summary.posture_label || (isDanger ? "High Risk" : totalFindings ? "Needs Review" : "Healthy");
  const reportNote = summary.note || (totalFindings ? "Security issues were detected in this repository." : "No critical findings detected for this repository.");
  const coverage = summary.coverage || {};
  const recommendations = Array.isArray(summary.recommendations) ? summary.recommendations.filter(Boolean) : [];
  
  // Apply danger theme if needed
  container.className = `seo-report-container ${isDanger ? 'report-danger' : ''}`;
  
  // Header Info
  $("repoReportTitle").textContent = `Report for ${summary.repo_name || summary.host || "github.com"}`;
  container.querySelector(".seo-report-subtitle").textContent = reportNote;
  $("repoGradeLetter").textContent = grade;
  $("repoGradeLabel").textContent = postureLabel;
  $("repoGradeCircle").className = `grade-circle grade-${grade.toLowerCase()}`;
  $("repoFindingsCount").textContent = String(totalFindings);

  // Meta Grid
  const metaGrid = container.querySelector(".seo-meta-grid");
  metaGrid.innerHTML = `
    <div class="mini-card">
      <span class="mini-card-label">TARGET URL</span>
      <span class="mini-card-value">${escapeHtml(data.query)}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">HOST</span>
      <span class="mini-card-value">${escapeHtml(summary.host || "github.com")}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">RISK SCORE</span>
      <span class="mini-card-value">${escapeHtml(String(summary.risk_score ?? 0))}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">FINDINGS</span>
      <span class="mini-card-value">${escapeHtml(String(totalFindings))}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">COVERAGE</span>
      <span class="mini-card-value">${escapeHtml(String(coverage.supported_target_count ?? 0))} supported targets</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">SCANNED ON</span>
      <span class="mini-card-value">${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">SCANNED BY</span>
      <span class="mini-card-value">${escapeHtml(summary.scanned_by || "Orion Intelligence")}</span>
    </div>
  `;

  const repoRecommendationsBox = $("repoRecommendationsBox");
  const repoRecommendationsContent = $("repoRecommendationsContent");
  const repoRecommendationsTitle = $("repoRecommendationsTitle");
  if (repoRecommendationsBox && repoRecommendationsContent && repoRecommendationsTitle) {
    repoRecommendationsBox.classList.remove("hidden");
    repoRecommendationsTitle.textContent = "AI Recommendations by DARKPULSE AI";
    const intro = grade === "A"
      ? "This repository is in a strong state right now. These practices help keep it there."
      : `DarkPulse graded this repository ${grade}. These improvements would strengthen the posture and move it closer to A.`;
    repoRecommendationsContent.innerHTML = renderDarkpulseRecommendationCard(
      recommendations.length ? { Actions: recommendations } : "",
      { note: intro }
    );
  }

  // Render Category Function
  const renderCategory = (title, items) => {
    if (!items || items.length === 0) return "";
    const severityClass = severity => {
      const normalized = String(severity || "UNKNOWN").toLowerCase();
      if (normalized === "critical") return "severity-critical";
      if (normalized === "high") return "severity-high";
      if (normalized === "medium") return "severity-medium";
      if (normalized === "low") return "severity-low";
      return "severity-unknown";
    };

    return `
      <section class="repo-findings-group">
        <h3 class="repo-section-title">${escapeHtml(title)} <span>${items.length}</span></h3>
      ${items.map(f => `
        <article class="repo-finding-card">
          <div class="repo-finding-body">
            <div class="repo-finding-head">
            <div class="finding-dot ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'dot-critical' : 'dot-medium'}"></div>
              <div class="repo-finding-copy">
                <span class="repo-finding-id">${escapeHtml(f.id)}</span>
                <span class="repo-finding-title">${escapeHtml(f.title)}</span>
                <span class="repo-finding-desc">${escapeHtml(f.description)}</span>
              </div>
            </div>
            <div class="repo-finding-tags">
              <span class="repo-severity-pill ${severityClass(f.severity)}">${escapeHtml(f.severity)} Risk</span>
              <span class="repo-confidence-badge">${escapeHtml(f.confidence)}</span>
            </div>
          </div>
          <div class="repo-snippet-box">
            <div class="snippet-header">
              <span class="snippet-label">Code snippet ⓘ</span>
            </div>
            <pre class="repo-snippet-desc">${escapeHtml(f.snippet || "No snippet available")}</pre>
          </div>
        </article>
      `).join("")}
      </section>
    `;
  };

  // Main Findings List
  let html = "";
  html += renderCategory("Security Findings", data.misconfigs);
  html += renderCategory("Secrets Findings", data.secrets);
  html += renderCategory("Vulnerability Findings", data.vulnerabilities);

  if (!html) {
    const manifestExamples = Array.isArray(coverage.manifest_examples) ? coverage.manifest_examples.slice(0, 4) : [];
    html = `
      <div class="repo-clean-state">
        <h3 class="repo-clean-title">${escapeHtml(postureLabel)}</h3>
        <p class="repo-clean-copy">${escapeHtml(reportNote)}</p>
        <div class="repo-clean-stats">
          <span>Manifests: ${escapeHtml(String(coverage.manifest_count ?? 0))}</span>
          <span>Configs: ${escapeHtml(String(coverage.config_count ?? 0))}</span>
          <span>Code Files: ${escapeHtml(String(coverage.code_file_count ?? 0))}</span>
        </div>
        ${manifestExamples.length ? `<div class="repo-clean-examples">${manifestExamples.map(example => `<span>${escapeHtml(example)}</span>`).join("")}</div>` : ""}
      </div>
    `;
  }

  $("repoFindingsList").innerHTML = html;
}




// --- SEO Analysis ---
async function runSeoScan() {
  const urlArg = $("seoInput").value.trim();
  if (!urlArg) return;
  setActionButtonBusy("seoSearchBtn", true, "Analyzing...");
  setExportToolbarState("seoExportBar", false);
  showReportScanLoading("seoStatus", "seoReport", "seo", "Queued: building live SEO posture and recommendations...");

  try {
    const data = await apiFetch(`/seo/analyze?url=${encodeURIComponent(urlArg)}`);
    if (data.status === "error") {
      state.scanExports.seo = null;
      restoreReportTemplate("seoReport", "seo");
      $("seoReport").classList.add("hidden");
      $("seoStatus").textContent = `Error: ${data.message}`;
      setExportToolbarState("seoExportBar", false);
      return;
    }
    restoreReportTemplate("seoReport", "seo");
    $("seoStatus").textContent = data.scan_message || "Analysis complete.";
    $("seoReport").classList.remove("hidden");
    state.scanExports.seo = data;
    renderSeoReport(data);
    setExportToolbarState("seoExportBar", true, `SEO report ready. Grade ${data.grade || "-"} with ${Object.keys(data.audits || {}).length} finding(s).`);
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.scanExports.seo = null;
    restoreReportTemplate("seoReport", "seo");
    $("seoReport").classList.add("hidden");
    $("seoStatus").textContent = `Scan failed: ${error.message}`;
    setExportToolbarState("seoExportBar", false);
  } finally {
    setActionButtonBusy("seoSearchBtn", false, "Analyzing...");
  }
}

function renderSeoReport(data) {
  const seoHealthGrade = data.seoHealthGrade || data.grade || "-";
  const scanConfidenceGrade = data.scanConfidenceGrade || "-";
  const crawlerVisibility = data.crawlerVisibility || {};
  const visibilityLevel = String(crawlerVisibility.level || "").toLowerCase();
  $("seoReportTitle").textContent = `Report for ${escapeHtml(data.url)}`;
  $("seoMetaUrl").textContent = data.url;
  $("seoMetaHost").textContent = new URL(data.url).hostname;
  $("seoMetaDate").textContent = data.timestamp;
  $("seoGradeLetter").textContent = seoHealthGrade;
  $("seoGradeLabel").textContent = "SEO Health";
  $("seoGradeCircle").className = `grade-circle grade-${String(seoHealthGrade).toLowerCase()}`;
  if ($("seoHealthGradeValue")) $("seoHealthGradeValue").textContent = seoHealthGrade;
  if ($("seoScanConfidenceValue")) $("seoScanConfidenceValue").textContent = scanConfidenceGrade;
  if ($("seoScanModeValue")) $("seoScanModeValue").textContent = data.scanModeUsed || "-";
  const warningBox = $("seoCrawlerWarning");
  const warningText = $("seoCrawlerWarningText");
  if (warningBox && warningText) {
    if (visibilityLevel === "low") {
      warningBox.classList.remove("hidden");
      warningText.textContent = "This page appears JavaScript-heavy, login-gated, or bot-protected. Some SEO findings are based only on limited crawler-visible HTML and should be treated as approximate.";
    } else if (visibilityLevel === "medium") {
      warningBox.classList.remove("hidden");
      warningText.textContent = crawlerVisibility.reason || "Rendered scan returned partial evidence, so some findings may need manual verification.";
    } else {
      warningBox.classList.add("hidden");
      warningText.textContent = "";
    }
  }

  const audits = data.audits || {};
  const auditItems = Object.keys(audits).map(id => audits[id]);
  $("seoFindingsCount").textContent = auditItems.length;
  $("seoFindingsList").innerHTML = auditItems.map(a => {
    const status = String(a.status || (Number(a.score) >= 0.85 ? "pass" : Number(a.score) >= 0.55 ? "warning" : "fail"));
    const evidence = String(a.evidence || "").trim();
    const recommendation = String(a.recommendation || "").trim();
    const confidence = String(a.confidence || "-");
    const evidenceSource = String(a.evidenceSource || "-");
    const note = String(a.note || "").trim();
    return `
    <div class="compact-item">
      <div class="compact-title">${escapeHtml(a.title)}</div>
      <div class="compact-item-footer">
        <span class="compact-meta">Score: ${a.score}</span>
        <span class="compact-meta">Status: ${escapeHtml(status)}</span>
        <span class="compact-meta">Confidence: ${escapeHtml(confidence)}</span>
        <span class="compact-meta">${escapeHtml(evidenceSource.replace(/_/g, " "))}</span>
      </div>
      <div class="compact-meta">${escapeHtml(a.description)}</div>
      ${evidence ? `<div class="compact-meta">Evidence: ${escapeHtml(evidence)}</div>` : ""}
      ${note ? `<div class="compact-meta">Note: ${escapeHtml(note)}</div>` : ""}
      ${recommendation ? `<div class="compact-meta">Fix: ${escapeHtml(recommendation)}</div>` : ""}
    </div>
  `;
  }).join("");

  const aiBox = $("seoAiSuggestionsBox");
  const aiContent = $("seoAiSuggestionsContent");
  const rawSuggestions = sanitizeAiBranding(String(data.ai_suggestions || "").trim());
  const aiMessage = sanitizeAiBranding(String(data.ai_message || "").trim());
  aiBox.classList.remove("hidden");
  aiContent.innerHTML = renderDarkpulseRecommendationCard(rawSuggestions, { note: aiMessage });
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add("show"), 100);
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => document.body.removeChild(toast), 300);
  }, 3000);
}
