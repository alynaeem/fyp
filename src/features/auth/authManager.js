export function createAuthManager({
  apiFetch,
  authLoading,
  prepareTwoFactorStage,
  bootstrapAuthenticatedSession,
  showError,
  clearErrors,
  setAuthStage,
  state,
  $,
  TOKEN_KEY,
  USER_ROLE_KEY,
  USER_NAME_KEY,
  AUTH_NOTICE_KEY
} = {}) {
  async function handleAuthSubmit() {
    console.debug('authManager.handleAuthSubmit invoked', { stage: state?.authStage });
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
        authLoading.showAuthLoading({
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
        if (typeof bootstrapAuthenticatedSession === "function") {
          await bootstrapAuthenticatedSession({
            username: state.authPendingUsername || $("loginUsername").value.trim(),
            role: data.role
          });
        } else {
          console.error('bootstrapAuthenticatedSession is not a function', bootstrapAuthenticatedSession);
          showError('loginError', 'Internal error: failed to initialize session.');
        }
        return;
      }

      const username = $("loginUsername").value.trim();
      button.textContent = "Signing In...";
      authLoading.showAuthLoading({
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
      console.debug('authManager.login response', data);

      if (data.mfa_required) {
        await authLoading.advanceAuthLoading(100, "Two-factor verification required. Opening OTP step...", {
          copy: "Your account needs an authenticator code before DarkPulse can finish signing you in.",
          delay: 220
        });
        authLoading.hideAuthLoading();
        prepareTwoFactorStage(data, username);
        return;
      }

      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_ROLE_KEY, data.role);
      localStorage.setItem(USER_NAME_KEY, username);
      sessionStorage.removeItem(AUTH_NOTICE_KEY);
      if (typeof bootstrapAuthenticatedSession === "function") {
        await bootstrapAuthenticatedSession({ username, role: data.role });
      } else {
        console.error('bootstrapAuthenticatedSession is not a function', bootstrapAuthenticatedSession);
        showError('loginError', 'Internal error: failed to initialize session.');
      }
    } catch (error) {
      authLoading.hideAuthLoading();
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

  return { handleAuthSubmit };
}
