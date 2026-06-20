function setAuthStage(stage) {
  state.authStage = stage;
  state.isRegistering = stage === "register";
  $("loginForm").classList.toggle("hidden", stage !== "login");
  $("registerForm").classList.toggle("hidden", stage !== "register");
  $("forgotForm").classList.toggle("hidden", stage !== "forgot");
  $("approvalForm").classList.toggle("hidden", stage !== "approval");
  $("mfaForm").classList.toggle("hidden", stage !== "mfa");
  $("authSubmitBtn").classList.toggle("hidden", stage === "approval");
  $("authSubmitBtn").textContent = stage === "register"
    ? "Request Access"
    : stage === "mfa"
      ? "Verify OTP"
      : stage === "forgot"
        ? "Request Reset"
        : "Sign In";
}

function clearAuthChallenge() {
  state.authChallengeToken = "";
  state.authChallengeType = "";
  state.authPendingUsername = "";
  state.authPendingRole = "";
  state.authQrCodeUrl = "";
  state.authManualSecret = "";
  $("mfaOtpInput").value = "";
  $("mfaQrImage").src = "";
  $("mfaManualSecret").textContent = "-";
  $("mfaQrSection").classList.add("hidden");
}

function toggleAuthMode() {
  clearErrors();
  clearAuthChallenge();
  setAuthStage(state.isRegistering ? "login" : "register");
}

function restoreAuthNotice() {
  const notice = sessionStorage.getItem(AUTH_NOTICE_KEY);
  if (!notice) return;
  sessionStorage.removeItem(AUTH_NOTICE_KEY);
  $("loginInfo").textContent = notice;
  $("loginInfo").classList.remove("hidden");
}

function prepareTwoFactorStage(payload, username) {
  clearErrors();
  clearAuthChallenge();
  state.authChallengeToken = payload.challenge_token || "";
  state.authChallengeType = payload.challenge_type || (payload.setup_required ? "setup" : "otp");
  state.authPendingUsername = username || payload.username || "";
  state.authPendingRole = payload.role || "";
  state.authQrCodeUrl = payload.qr_code_url || "";
  state.authManualSecret = payload.manual_secret || "";

  $("mfaTitle").textContent = payload.setup_required ? "Set up your authenticator" : "Enter your verification code";
  $("mfaCopy").textContent = payload.setup_required
    ? "Scan this QR code once in Google Authenticator, Authy, or another app, then enter the 6-digit code to finish signing in."
    : "2FA is enabled for this account. Enter the current 6-digit code from your authenticator app to continue.";
  $("mfaSecretHint").textContent = payload.setup_required
    ? "If the QR code does not load, type this key manually into your authenticator app."
    : "This setup has already been completed before, so only the OTP is required now.";
  $("mfaManualSecret").textContent = state.authManualSecret || "-";
  $("mfaQrSection").classList.toggle("hidden", !payload.setup_required);
  $("mfaQrImage").src = state.authQrCodeUrl || "";
  $("mfaOtpInput").value = "";
  setAuthStage("mfa");
}

function showError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearErrors() {
  ["loginError", "registerError", "forgotError", "mfaError"].forEach(id => {
    $(id).textContent = "";
    $(id).classList.add("hidden");
  });
  $("loginInfo").textContent = "";
  $("loginInfo").classList.add("hidden");
}

async function handleAuthSubmit() {
  clearErrors();
  const button = $("authSubmitBtn");
  const originalLabel = button.textContent;
  button.disabled = true;

  try {
    if (state.authStage === "register") {
      const requestedUsername = $("regUsername").value.trim();
      await apiFetch("/auth/register", true, {
        method: "POST",
        body: {
          username: requestedUsername,
          password: $("regPassword").value,
          email: $("regEmail").value.trim(),
          name: $("regName").value.trim()
        }
      });
      $("regName").value = "";
      $("regEmail").value = "";
      $("regUsername").value = "";
      $("regPassword").value = "";
      setAuthStage("login");
      $("loginUsername").value = requestedUsername;
      $("loginPassword").value = "";
      $("loginInfo").textContent = "Registration submitted. Wait for admin approval before signing in.";
      $("loginInfo").classList.remove("hidden");
      return;
    }

    if (state.authStage === "forgot") {
      const data = await apiFetch("/auth/password-reset-request", true, {
        method: "POST",
        body: {
          identity: $("forgotIdentity").value.trim(),
          message: $("forgotMessage").value.trim()
        }
      });
      clearErrors();
      setAuthStage("login");
      $("forgotIdentity").value = "";
      $("forgotMessage").value = "";
      $("loginInfo").textContent = data.message || "Reset request submitted for review.";
      $("loginInfo").classList.remove("hidden");
      return;
    }

    if (state.authStage === "mfa") {
      button.textContent = "Verifying OTP...";
      showAuthLoading({
        kicker: "Two-Factor Verification",
        title: "Confirming your one-time password",
        copy: "DarkPulse is validating your OTP and restoring your approved analyst session.",
        stage: "Checking the 6-digit code from your authenticator...",
        progress: 18,
        cap: 86
      });
      const data = await apiFetch("/auth/login/verify-otp", true, {
        method: "POST",
        body: {
          challenge_token: state.authChallengeToken,
          otp: $("mfaOtpInput").value.trim()
        }
      });

      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_ROLE_KEY, data.role);
      localStorage.setItem(USER_NAME_KEY, state.authPendingUsername || $("loginUsername").value.trim());
      sessionStorage.removeItem(AUTH_NOTICE_KEY);
      await bootstrapAuthenticatedSession({
        username: state.authPendingUsername || $("loginUsername").value.trim(),
        role: data.role
      });
      return;
    }

    const username = $("loginUsername").value.trim();
    button.textContent = "Signing In...";
    showAuthLoading({
      kicker: "Authenticating",
      title: "Signing in to DarkPulse",
      copy: "We are verifying your credentials and preparing the local threat intelligence console.",
      stage: "Checking username and password...",
      progress: 12,
      cap: 84
    });
    const data = await apiFetch("/auth/login", true, {
      method: "POST",
      body: {
        username,
        password: $("loginPassword").value
      }
    });

    if (data.mfa_required) {
      await advanceAuthLoading(100, "Two-factor verification required. Opening OTP step...", {
        copy: "Your account needs an authenticator code before DarkPulse can finish signing you in.",
        delay: 220
      });
      hideAuthLoading();
      prepareTwoFactorStage(data, username);
      return;
    }

    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_ROLE_KEY, data.role);
    localStorage.setItem(USER_NAME_KEY, username);
    sessionStorage.removeItem(AUTH_NOTICE_KEY);
    await bootstrapAuthenticatedSession({ username, role: data.role });
  } catch (error) {
    hideAuthLoading();
    const errorTarget = state.authStage === "register"
      ? "registerError"
      : state.authStage === "mfa"
        ? "mfaError"
        : state.authStage === "forgot"
          ? "forgotError"
          : "loginError";
    showError(errorTarget, error.message);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
    if (state.authStage === "login") {
      button.textContent = "Sign In";
    } else if (state.authStage === "register") {
      button.textContent = "Request Access";
    } else if (state.authStage === "forgot") {
      button.textContent = "Request Reset";
    } else if (state.authStage === "mfa") {
      button.textContent = "Verify OTP";
    }
  }
}

function setActiveNavigation(target) {
  document.querySelectorAll(".nav-item").forEach(item => {
    const itemTarget = item.dataset.view || item.dataset.tab;
    item.classList.toggle("active", itemTarget === target);
  });
}

function getActiveFeedFilters() {
  return normalizeFeedFilters(state.feedFilters);
}

function countActiveFeedFilters() {
  const filters = getActiveFeedFilters();
  return [filters.startDate, filters.endDate, filters.network, filters.topic].filter(Boolean).length;
}

function buildFeedFilterSummary(filters = getActiveFeedFilters()) {
  const parts = [];
  if (filters.startDate) parts.push(`From ${filters.startDate}`);
  if (filters.endDate) parts.push(`To ${filters.endDate}`);
  if (filters.network) parts.push(filters.network === "onion" ? "Onion / Tor" : "Clearnet");
  if (filters.topic) parts.push(`Topic ${filters.topic}`);
  return parts.length ? parts.join(" • ") : "No feed filters applied.";
}

function renderFeedFilterState() {
  const filters = getActiveFeedFilters();
  const activeCount = countActiveFeedFilters();
  const button = $("feedFilterBtn");
  const bar = $("feedFilterBar");
  const note = $("feedFilterNote");
  const chips = $("feedFilterChips");
  const status = $("feedFilterStatus");

  if (button) {
    button.textContent = activeCount ? `Filters (${activeCount})` : "Filters";
  }

  if (status) {
    status.textContent = buildFeedFilterSummary(filters);
  }

  if (!bar || !note || !chips) return;

  if (!activeCount) {
    bar.classList.add("hidden");
    note.textContent = "No feed filters applied.";
    chips.innerHTML = "";
    return;
  }

  note.textContent = buildFeedFilterSummary(filters);
  chips.innerHTML = [
    filters.startDate ? `<span class="feed-filter-chip">Start ${escapeHtml(filters.startDate)}</span>` : "",
    filters.endDate ? `<span class="feed-filter-chip">End ${escapeHtml(filters.endDate)}</span>` : "",
    filters.network ? `<span class="feed-filter-chip">${escapeHtml(filters.network === "onion" ? "Onion / Tor" : "Clearnet")}</span>` : "",
    filters.topic ? `<span class="feed-filter-chip">Topic ${escapeHtml(filters.topic)}</span>` : ""
  ].filter(Boolean).join("");
  bar.classList.remove("hidden");
}

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

function openFeedFiltersModal() {
  $("feedFilterStartDate").value = state.feedFilters.startDate || "";
  $("feedFilterEndDate").value = state.feedFilters.endDate || "";
  $("feedFilterNetwork").value = state.feedFilters.network || "";
  $("feedFilterTopic").value = state.feedFilters.topic || "";
  renderFeedFilterState();
  $("feedFiltersBackdrop").classList.remove("hidden");
}

function closeFeedFiltersModal() {
  $("feedFiltersBackdrop").classList.add("hidden");
}

/* ── Floating Chatbot Widget ────────────────────────────────────────── */
let _dpChatBusy = false;

function isAuthRouteOrLoginVisible() {
  const path = `${window.location.pathname || ""} ${window.location.hash || ""}`.toLowerCase();
  return path.includes("/login")
    || path.includes("/auth")
    || path.includes("/signin")
    || !$("loginBackdrop")?.classList.contains("hidden")
    || $("appWrapper")?.classList.contains("hidden");
}

function setChatAvailability(enabled) {
  const shouldEnable = Boolean(enabled) && !isAuthRouteOrLoginVisible();
  const headerButton = $("aiChatLaunchBtn");
  const fab = $("dpChatFab");
  const widget = $("dpChatWidget");
  if (headerButton) {
    headerButton.classList.toggle("hidden", !shouldEnable);
    headerButton.style.display = shouldEnable ? "" : "none";
  }
  if (!shouldEnable) {
    fab?.classList.add("hidden");
    widget?.classList.add("hidden");
    return;
  }
  if (widget?.classList.contains("hidden")) {
    fab?.classList.remove("hidden");
  }
}

function dpChatShow() {
  if (isAuthRouteOrLoginVisible()) return;
  $("dpChatWidget").classList.remove("hidden");
  $("dpChatFab").classList.add("hidden");
  setTimeout(() => $("dpChatInput").focus(), 60);
}

function dpChatHide() {
  $("dpChatWidget").classList.add("hidden");
  if (!isAuthRouteOrLoginVisible()) $("dpChatFab").classList.remove("hidden");
}

function dpChatMinimize() {
  $("dpChatWidget").classList.add("hidden");
  if (!isAuthRouteOrLoginVisible()) $("dpChatFab").classList.remove("hidden");
}

function dpChatClear() {
  $("dpChatMessages").innerHTML = `
    <div class="dp-chat-welcome">
      <div class="dp-chat-welcome-icon">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
      </div>
      <p class="dp-chat-welcome-title">DARKPULSE Chatbot</p>
      <p class="dp-chat-welcome-text">Ask about threat actors, leaks, CVEs, ransomware campaigns, or any topic in the local MongoDB.</p>
    </div>
  `;
}

function dpChatShowFab() {
  if (!isAuthRouteOrLoginVisible() && $("dpChatWidget").classList.contains("hidden")) {
    $("dpChatFab").classList.remove("hidden");
  }
}

function _dpScrollToBottom() {
  const el = $("dpChatMessages");
  el.scrollTop = el.scrollHeight;
}

function _dpAddUserMessage(text) {
  const welcome = $("dpChatMessages").querySelector(".dp-chat-welcome");
  if (welcome) welcome.remove();

  const now = new Date();
  const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const msg = document.createElement("div");
  msg.className = "dp-msg dp-msg-user";
  msg.innerHTML = `
    <div class="dp-msg-bubble">${escapeHtml(sanitizeAiBranding(text))}</div>
    <div class="dp-msg-meta">${time}</div>
  `;
  $("dpChatMessages").appendChild(msg);
  _dpScrollToBottom();
}

function _dpAddThinking() {
  const el = document.createElement("div");
  el.className = "dp-msg dp-msg-ai";
  el.id = "dpMsgThinking";
  el.innerHTML = `
    <div class="dp-msg-bubble dp-msg-thinking">
      <div class="dp-msg-thinking-dots"><span></span><span></span><span></span></div>
      Searching intelligence...
    </div>
  `;
  $("dpChatMessages").appendChild(el);
  _dpScrollToBottom();
}

function _dpRemoveThinking() {
  const el = $("dpMsgThinking");
  if (el) el.remove();
}

function _dpSourceLabel(doc) {
  // Build a human-readable label from the document reference
  const aid = doc.aid || doc._id || "";
  const field = doc.field || "";

  // Try to extract a meaningful title from the preview
  const preview = doc.preview || "";
  const titleMatch = preview.match(/Title:\s*(.+?)(?:\n|$)/i);
  const summaryMatch = preview.match(/Summary:\s*(.+?)(?:\n|$)/i);
  const sourceMatch = preview.match(/Source(?:\sName)?:\s*(.+?)(?:\n|$)/i);

  if (titleMatch && titleMatch[1].trim().length > 5) {
    return titleMatch[1].trim().slice(0, 65);
  }
  if (summaryMatch && summaryMatch[1].trim().length > 5) {
    return summaryMatch[1].trim().slice(0, 65);
  }
  if (sourceMatch && sourceMatch[1].trim().length > 3) {
    return sourceMatch[1].trim().slice(0, 65);
  }

  // Fallback: use the aid/field combo but make it readable
  if (aid && field && field !== "record" && field !== "content") {
    return `${field.charAt(0).toUpperCase() + field.slice(1)} · ${aid.slice(0, 20)}`;
  }
  if (aid) {
    // Try to extract source from the aid pattern like "LEAK_ITEMS:raw:xxxx"
    const aidParts = aid.split(":");
    if (aidParts.length >= 2) {
      const type = aidParts[0].replace(/_ITEMS$/i, "").replace(/_/g, " ");
      return `${type.charAt(0).toUpperCase() + type.slice(1).toLowerCase()} record · ${aidParts.slice(-1)[0].slice(0, 12)}`;
    }
    return `Intelligence record · ${aid.slice(0, 20)}`;
  }
  return `Source document #${Math.random().toString(36).slice(2, 6)}`;
}

