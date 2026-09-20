export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export const TOKEN_KEY = "secure_ai_gateway_token";
export const USER_KEY = "secure_ai_gateway_user";

export function getStoredToken() {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(TOKEN_KEY) ?? "";
}

export function authHeaders(token = getStoredToken()) {
  return token ? { authorization: `Bearer ${token}` } : {};
}

export function apiErrorMessage(detail: unknown, fallback = "Request failed") {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (detail && typeof detail === "object") {
    const errorDetail = detail as { code?: unknown; message?: unknown };
    const code = typeof errorDetail.code === "string" ? errorDetail.code : "";
    const message = typeof errorDetail.message === "string" ? errorDetail.message : "";
    const parts = [code, message].filter(Boolean);
    if (parts.length) return parts.join(": ");
  }
  return fallback;
}
