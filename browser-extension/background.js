// Service worker: the only part of the extension that talks to the gateway.
// Content scripts run inside the AI website's origin, so a fetch from there is
// subject to that site's CORS rules and would be blocked by the gateway; the
// service worker is covered by host_permissions instead.

const DEFAULT_BACKEND = "http://localhost:8000";

async function settings() {
  const stored = await chrome.storage.local.get(["backendUrl", "token", "user"]);
  return {
    backendUrl: (stored.backendUrl || DEFAULT_BACKEND).replace(/\/$/, ""),
    token: stored.token || "",
    user: stored.user || null,
  };
}

function errorMessage(body, fallback) {
  const detail = body && body.detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail.message === "string") return detail.message;
  return fallback;
}

async function callGateway(path, { method = "GET", body, auth = true } = {}) {
  const { backendUrl, token } = await settings();
  if (auth && !token) {
    return { ok: false, status: 401, error: "Not signed in to the gateway. Open the extension popup to log in." };
  }
  let response;
  try {
    response = await fetch(`${backendUrl}${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(auth ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    return { ok: false, status: 0, error: `Gateway not reachable at ${backendUrl}.` };
  }
  const data = await response.json().catch(() => null);
  if (response.status === 401 && auth) {
    await chrome.storage.local.remove(["token", "user"]);
    return { ok: false, status: 401, error: "Gateway session expired. Log in again from the extension popup." };
  }
  if (!response.ok) {
    return { ok: false, status: response.status, error: errorMessage(data, `Gateway error (${response.status}).`) };
  }
  return { ok: true, status: response.status, data };
}

// Toolbar badge for the tab the prompt came from: nothing for ALLOW,
// "!" when values were replaced, "X" when the prompt was blocked.
const BADGES = {
  SANITIZE: { text: "!", color: "#d97706" },
  BLOCK: { text: "X", color: "#d92d20" },
};

function showBadge(tabId, decision) {
  if (tabId === undefined || !chrome.action) return;
  const badge = BADGES[decision];
  chrome.action.setBadgeText({ tabId, text: badge ? badge.text : "" });
  if (badge) chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

async function scanPrompt({ prompt, service }, sender = {}) {
  const result = await callGateway("/api/v1/sanitize", {
    method: "POST",
    body: { prompt, service, source: "browser-extension" },
  });
  if (result.ok) {
    const { decision, riskLevel, riskScore, replacements, reason } = result.data;
    // Keep a summary for the popup only; the prompt text is never stored.
    await chrome.storage.local.set({
      lastScan: {
        decision,
        riskLevel,
        riskScore,
        reason,
        service,
        replaced: replacements.length,
        at: new Date().toISOString(),
      },
    });
    showBadge(sender.tab && sender.tab.id, decision);
  }
  return result;
}

async function login({ email, password }) {
  const result = await callGateway("/auth/login", { method: "POST", body: { email, password }, auth: false });
  if (result.ok) {
    await chrome.storage.local.set({ token: result.data.token, user: result.data.user });
    return { ok: true, data: { user: result.data.user } };
  }
  return result;
}

async function health() {
  return callGateway("/health", { auth: false });
}

const handlers = {
  SCAN_PROMPT: scanPrompt,
  LOGIN: login,
  LOGOUT: async () => {
    await chrome.storage.local.remove(["token", "user", "lastScan"]);
    return { ok: true };
  },
  HEALTH: health,
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only accept messages from this extension's own pages and content scripts.
  if (sender.id !== chrome.runtime.id) return false;
  const handler = handlers[message && message.type];
  if (!handler) return false;
  handler(message.payload || {}, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, status: 0, error: String(error && error.message ? error.message : error) }));
  return true; // keep the channel open for the async response
});
