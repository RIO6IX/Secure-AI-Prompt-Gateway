// Tests for the extension service worker (background.js).
//
// Loads the real background.js in a VM with a mocked chrome.* API and points
// it at a local mock gateway, so the fetch/auth/storage logic runs as it
// would in Chrome.  Run from the repository root:
//
//     cd browser-extension && npm test

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { after, before, beforeEach, test } from "node:test";
import vm from "node:vm";

const VALID_PASSWORD = "Gateway#Pass2026";
const TOKEN = "token-123";
let gatewayUrl;
let server;
let lastSanitizeBody;
let sanitizeStatus = 200;

const DECISIONS = {
  "hello": { decision: "ALLOW", sanitizedPrompt: "hello", replacements: [] },
  "mail nimal@company.lk": {
    decision: "SANITIZE",
    sanitizedPrompt: "mail [EMAIL_ADDRESS_1]",
    replacements: [{ placeholder: "[EMAIL_ADDRESS_1]", entity_type: "EMAIL_ADDRESS" }],
  },
  "password = hunter22": { decision: "BLOCK", sanitizedPrompt: "", replacements: [{ placeholder: "[PASSWORD_1]" }] },
};

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

before(async () => {
  server = createServer(async (request, response) => {
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    if (request.url === "/health") return json(response, 200, { status: "healthy" });
    if (request.url === "/auth/login") {
      if (body.password !== VALID_PASSWORD) return json(response, 401, { detail: "Invalid email or password" });
      return json(response, 200, { token: TOKEN, user: { name: "Ext User", email: body.email, role: "user" } });
    }
    if (request.url === "/api/v1/sanitize") {
      if (request.headers.authorization !== `Bearer ${TOKEN}`) return json(response, 401, { detail: "Invalid or expired login" });
      lastSanitizeBody = body;
      if (sanitizeStatus !== 200) return json(response, sanitizeStatus, { detail: "Too many prompts in a short time." });
      const verdict = DECISIONS[body.prompt];
      return json(response, 200, { ...verdict, riskLevel: "LOW", riskScore: 10, reason: "test", auditId: "AUD-1" });
    }
    return json(response, 404, { detail: "not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  gatewayUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

let store;
let badges;
let listener;

async function loadBackground() {
  store = { backendUrl: gatewayUrl };
  badges = {};
  const chrome = {
    runtime: { id: "ext-id", onMessage: { addListener: (fn) => { listener = fn; } } },
    storage: {
      local: {
        get: async (keys) => Object.fromEntries(keys.filter((key) => key in store).map((key) => [key, store[key]])),
        set: async (values) => { Object.assign(store, values); },
        remove: async (keys) => { keys.forEach((key) => delete store[key]); },
      },
    },
    action: {
      setBadgeText: ({ tabId, text }) => { badges[tabId] = text; },
      setBadgeBackgroundColor: () => {},
    },
  };
  const source = await readFile(new URL("../background.js", import.meta.url), "utf8");
  vm.runInNewContext(source, { chrome, fetch, console, URL });
}

function send(type, payload, sender = { id: "ext-id", tab: { id: 7 } }) {
  return new Promise((resolve) => {
    const handled = listener({ type, payload }, sender, resolve);
    if (!handled) resolve("IGNORED");
  });
}

beforeEach(async () => {
  sanitizeStatus = 200;
  lastSanitizeBody = undefined;
  await loadBackground();
});

test("scanning before login is refused without calling the gateway", async () => {
  const result = await send("SCAN_PROMPT", { prompt: "hello", service: "ChatGPT" });
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
  assert.equal(lastSanitizeBody, undefined);
});

test("login stores the token and a wrong password surfaces the gateway error", async () => {
  const bad = await send("LOGIN", { email: "ext@acme.lk", password: "nope" });
  assert.deepEqual([bad.ok, bad.error], [false, "Invalid email or password"]);
  assert.equal(store.token, undefined);

  const good = await send("LOGIN", { email: "ext@acme.lk", password: VALID_PASSWORD });
  assert.equal(good.ok, true);
  assert.equal(store.token, TOKEN);
});

test("each decision is returned, summarised without prompt text, and badged", async () => {
  await send("LOGIN", { email: "ext@acme.lk", password: VALID_PASSWORD });

  for (const [prompt, expected, badge] of [
    ["hello", "ALLOW", ""],
    ["mail nimal@company.lk", "SANITIZE", "!"],
    ["password = hunter22", "BLOCK", "X"],
  ]) {
    const result = await send("SCAN_PROMPT", { prompt, service: "ChatGPT" });
    assert.equal(result.data.decision, expected);
    assert.equal(lastSanitizeBody.source, "browser-extension");
    assert.equal(badges[7], badge);
    assert.ok(!JSON.stringify(store.lastScan).includes(prompt), "prompt text must not be stored");
  }
  assert.equal(store.lastScan.decision, "BLOCK");
});

test("rate limiting and outages are reported, not thrown", async () => {
  await send("LOGIN", { email: "ext@acme.lk", password: VALID_PASSWORD });
  sanitizeStatus = 429;
  const limited = await send("SCAN_PROMPT", { prompt: "hello", service: "ChatGPT" });
  assert.deepEqual([limited.ok, limited.status], [false, 429]);
  assert.match(limited.error, /Too many prompts/);

  store.backendUrl = "http://127.0.0.1:9";
  const offline = await send("SCAN_PROMPT", { prompt: "hello", service: "ChatGPT" });
  assert.deepEqual([offline.ok, offline.status], [false, 0]);
  assert.match(offline.error, /not reachable/);
});

test("an expired session clears the stored token", async () => {
  await send("LOGIN", { email: "ext@acme.lk", password: VALID_PASSWORD });
  store.token = "stale";
  const result = await send("SCAN_PROMPT", { prompt: "hello", service: "ChatGPT" });
  assert.equal(result.status, 401);
  assert.equal(store.token, undefined);
});

test("messages from other extensions are ignored", async () => {
  const result = await send("SCAN_PROMPT", { prompt: "hello" }, { id: "some-other-extension" });
  assert.equal(result, "IGNORED");
});
