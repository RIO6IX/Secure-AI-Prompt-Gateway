import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);

test("secure chat is wired to the inspection backend instead of mock data", async () => {
  const [page, chat, backend, hosting] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/SecureChatWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../python_gateway/app.py", import.meta.url), "utf8"),
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /<SecureChatWorkspace \/>/);
  assert.match(chat, /API_BASE_URL/);
  assert.match(chat, /\/inspect/);
  assert.match(chat, /TOKEN_KEY/);
  assert.match(chat, /authHeaders/);
  assert.match(chat, /New secure chat/);
  assert.match(chat, /How can I help securely\?/);
  assert.match(chat, /Clear current chat/);
  assert.match(chat, /href="\/audit-logs"/);
  assert.match(chat, /status === "Blocked"/);
  assert.match(chat, /status === "Sanitized"/);
  assert.doesNotMatch(chat, /Ingest Test Event|dashboard-live-ingest|sk-proj-demo-secret-value/);

  assert.match(backend, /DB_PATH = BASE_DIR \/ "audit_logs.sqlite3"/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS audit_events/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS users/);
  assert.match(hosting, /"d1":\s*null/);
});

test("separate audit, settings, and admin pages exist", async () => {
  const [auditPage, settingsPage, adminPage, standalone, backend] = await Promise.all([
    readFile(new URL("../app/audit-logs/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/system-settings/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/admin/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/StandalonePages.tsx", import.meta.url), "utf8"),
    readFile(new URL("../python_gateway/app.py", import.meta.url), "utf8"),
  ]);

  assert.match(auditPage, /<AuditLogsPage \/>/);
  assert.match(settingsPage, /<SystemSettingsPage \/>/);
  assert.match(adminPage, /<AdminPanelPage \/>/);
  assert.match(standalone, /\/admin\/users/);
  assert.match(standalone, /method: "DELETE"/);
  assert.match(standalone, /Delete user/);
  assert.match(standalone, /admin - all privileges/);
  assert.match(standalone, /auditor - read only audit log/);
  assert.match(standalone, /user - read only dashboard/);
  assert.match(backend, /Role = Literal\["admin", "auditor", "user"\]/);
  assert.match(backend, /require_role\(current_user, \{"admin"\}\)/);
  assert.match(backend, /@app\.delete\("\/admin\/users\/\{user_id\}"\)/);
  assert.match(backend, /require_role\(current_user, \{"admin", "auditor"\}\)/);
});

test("login and register pages use the local Python backend", async () => {
  const [loginPage, registerPage, authForm, api] = await Promise.all([
    readFile(new URL("../app/login/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/register/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/AuthForm.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/lib/api.ts", import.meta.url), "utf8"),
  ]);

  assert.match(loginPage, /<AuthForm mode="login" \/>/);
  assert.match(registerPage, /<AuthForm mode="register" \/>/);
  assert.match(authForm, /\/auth\/\$\{mode\}/);
  assert.match(authForm, /localStorage\.setItem\(TOKEN_KEY/);
  assert.match(api, /http:\/\/localhost:8000/);
});

test("removes starter preview assets and metadata", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.doesNotMatch(page, /SkeletonPreview|_sites-preview|codex-preview/);
  assert.doesNotMatch(layout, /Starter Project|codex-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);

  await assert.rejects(access(new URL("app/_sites-preview/SkeletonPreview.tsx", templateRoot)));
});
