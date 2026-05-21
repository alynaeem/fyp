import { API_BASE_KEY, DEFAULT_API_BASE, STORAGE_KEY, TOKEN_KEY } from "../core/config.js";

export function getBase() {
  return localStorage.getItem(API_BASE_KEY) || DEFAULT_API_BASE;
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export async function apiFetch(path, noAuth = false, options = {}) {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json"
  };

  const token = getToken();
  const apiKey = localStorage.getItem(STORAGE_KEY) || "";
  if (!noAuth && token) headers.Authorization = `Bearer ${token}`;
  if (apiKey) headers["X-API-Key"] = apiKey;

  const response = await fetch(getBase() + path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: options.signal
  });

  if (response.status === 401 && !noAuth) {
    if (typeof window !== "undefined" && typeof window.handleLogout === "function") {
      window.handleLogout();
    }
    throw new Error("Session expired");
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}
