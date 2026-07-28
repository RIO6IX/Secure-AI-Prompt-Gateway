import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);

test("dashboard is wired to the audit backend instead of mock data", async () => {
  const [page, dashboard, auditRoute, schema, hosting] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/AuditDashboard.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/audit/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /<AuditDashboard \/>/);
  assert.match(dashboard, /API_BASE_URL/);
  assert.match(dashboard, /apiFetch<AuditResponse>\("\/audit"\)/);
  assert.match(dashboard, /\/inspect/);
  assert.match(dashboard, /\/reports\/export/);
  assert.match(dashboard, /API_BASE_URL/);
  assert.match(dashboard, /TOKEN_KEY/);
  assert.match(dashboard, /Ingest Test Event/);
  assert.match(dashboard, /No records in the backend yet/);
  assert.match(dashboard, /Prompt Monitor/);
  assert.match(dashboard, /setActiveView/);
  assert.doesNotMatch(dashboard, /12,842|john\.doe@company\.com|API key detected in prompt/i);

  assert.match(auditRoute, /CREATE TABLE IF NOT EXISTS audit_events/);
  assert.match(auditRoute, /INSERT INTO audit_events/);
  assert.match(auditRoute, /SELECT[\s\S]+FROM audit_events/);
  assert.match(schema, /sqliteTable\("audit_events"/);
  assert.match(hosting, /"d1":\s*"DB"/);
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
