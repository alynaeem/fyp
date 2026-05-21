export function createAuthLoadingModule({ state, $, sleep, AUTH_PROGRESS_TICK_MS }) {
  function clearAuthLoadingTimer() {
    clearInterval(state.authLoadingTimer);
    state.authLoadingTimer = null;
  }

  function renderAuthLoading(progress = state.authLoadingProgress) {
    const safeProgress = Math.max(0, Math.min(100, Math.round(progress)));
    state.authLoadingProgress = safeProgress;
    $("authLoadingRing").style.setProperty("--auth-progress", `${safeProgress}%`);
    $("authLoadingPercent").textContent = `${safeProgress}%`;
  }

  function setAuthLoadingText({
    kicker = "",
    title = "",
    copy = "",
    stage = ""
  } = {}) {
    if (kicker) $("authLoadingKicker").textContent = kicker;
    if (title) $("authLoadingTitle").textContent = title;
    if (copy) $("authLoadingCopy").textContent = copy;
    if (stage) $("authLoadingStage").textContent = stage;
  }

  function showAuthLoading({
    kicker = "Authenticating",
    title = "Signing in to DarkPulse",
    copy = "Verifying your credentials and preparing the live console.",
    stage = "Checking username and password...",
    progress = 8,
    cap = 72
  } = {}) {
    state.authLoadingActive = true;
    state.authLoadingCap = Math.max(progress, cap);
    $("authLoadingOverlay").classList.remove("hidden");
    $("authShell").classList.add("auth-shell-loading");
    setAuthLoadingText({ kicker, title, copy, stage });
    renderAuthLoading(progress);
    clearAuthLoadingTimer();
    state.authLoadingTimer = setInterval(() => {
      if (!state.authLoadingActive || state.authLoadingProgress >= state.authLoadingCap) return;
      const current = state.authLoadingProgress;
      const step = current < 36 ? 4 : current < 64 ? 3 : current < 82 ? 2 : 1;
      renderAuthLoading(Math.min(state.authLoadingCap, current + step));
    }, AUTH_PROGRESS_TICK_MS);
  }

  async function advanceAuthLoading(target, stage = "", options = {}) {
    if (!state.authLoadingActive) return;
    state.authLoadingCap = Math.max(state.authLoadingCap, target);
    setAuthLoadingText({
      kicker: options.kicker || "",
      title: options.title || "",
      copy: options.copy || "",
      stage
    });
    renderAuthLoading(Math.max(state.authLoadingProgress, target));
    await sleep(options.delay ?? 140);
  }

  function hideAuthLoading() {
    state.authLoadingActive = false;
    state.authLoadingCap = 0;
    clearAuthLoadingTimer();
    $("authLoadingOverlay").classList.add("hidden");
    $("authShell").classList.remove("auth-shell-loading");
    renderAuthLoading(0);
    setAuthLoadingText({
      kicker: "Authenticating",
      title: "Signing in to DarkPulse",
      copy: "Verifying your credentials and preparing the live console.",
      stage: "Checking username and password..."
    });
  }

  return {
    clearAuthLoadingTimer,
    renderAuthLoading,
    setAuthLoadingText,
    showAuthLoading,
    advanceAuthLoading,
    hideAuthLoading
  };
}
