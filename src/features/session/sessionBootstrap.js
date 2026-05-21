export function createSessionBootstrapModule({
  state,
  $,
  showToast,
  checkHealth,
  pollSmartUpdateStatus,
  switchView,
  scheduleRefresh,
  setLastUpdated,
  applyAuthenticatedIdentity,
  advanceAuthLoading,
  hideAuthLoading
}) {
  const notify = typeof showToast === "function" ? showToast : () => {};

  async function warmAuthenticatedWorkspace() {
    const bootWarnings = [];

    const healthTask = checkHealth();
    const smartUpdateTask = pollSmartUpdateStatus(true);
    const homepageTask = switchView("homepage");

    const [healthResult, smartUpdateResult, homepageResult] = await Promise.allSettled([
      healthTask,
      smartUpdateTask,
      homepageTask
    ]);

    if (healthResult.status === "rejected") {
      console.error(healthResult.reason);
      bootWarnings.push("health");
    }

    if (smartUpdateResult.status === "rejected") {
      console.error(smartUpdateResult.reason);
      bootWarnings.push("automation");
    }

    if (homepageResult.status === "rejected") {
      console.error(homepageResult.reason);
      bootWarnings.push("homepage");
    }

    setLastUpdated();
    scheduleRefresh();

    if (bootWarnings.length) {
      notify("Signed in. Some dashboard panels are still warming up in the background.", "info");
    }
  }

  async function bootstrapAuthenticatedSession({ username, role }) {
    applyAuthenticatedIdentity(role, username, { keepBackdrop: true });
    await advanceAuthLoading(78, "Session accepted. Opening your console...", {
      copy: "DarkPulse has verified your access. The dashboard will keep loading in the background.",
      delay: 120
    });
    await advanceAuthLoading(100, "Access granted. Entering DarkPulse now.", {
      copy: "You are signed in. Live cards, heatmap, and automation status are warming up.",
      delay: 180
    });

    $("loginBackdrop").classList.add("hidden");
    hideAuthLoading();
    void warmAuthenticatedWorkspace().catch(error => {
      console.error(error);
      notify("Signed in, but some dashboard sections are still loading.", "info");
    });
  }

  return {
    warmAuthenticatedWorkspace,
    bootstrapAuthenticatedSession
  };
}
