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
