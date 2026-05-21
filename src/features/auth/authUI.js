export function createAuthUIModule({ state, $, AUTH_NOTICE_KEY } = {}) {
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

  return {
    setAuthStage,
    clearAuthChallenge,
    toggleAuthMode,
    restoreAuthNotice,
    prepareTwoFactorStage,
    showError,
    clearErrors
  };
}

export function attachAuthUIHandlers({ $, handleAuthSubmit, authUI } = {}) {
  // authUI is optional; if provided, prefer its helpers
  const toggleAuthMode = authUI?.toggleAuthMode || (() => {});
  const clearErrors = authUI?.clearErrors || (() => {});
  const clearAuthChallenge = authUI?.clearAuthChallenge || (() => {});
  const setAuthStage = authUI?.setAuthStage || (() => {});

  $("authSubmitBtn").addEventListener("click", handleAuthSubmit);
  $("showRegisterLink").addEventListener("click", event => {
    event.preventDefault();
    toggleAuthMode();
  });
  $("showApprovalLink").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("approval");
  });
  $("showForgotLink").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("forgot");
  });
  $("showLoginLink").addEventListener("click", event => {
    event.preventDefault();
    toggleAuthMode();
  });
  $("forgotBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("login");
  });
  $("approvalBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("login");
  });
  $("approvalOpenRegister").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("register");
  });
  $("mfaBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("login");
  });
  ["loginUsername", "loginPassword", "mfaOtpInput", "regName", "regEmail", "regUsername", "regPassword", "forgotIdentity", "forgotMessage"].forEach(id => {
    $(id).addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      handleAuthSubmit();
    });
  });
}

