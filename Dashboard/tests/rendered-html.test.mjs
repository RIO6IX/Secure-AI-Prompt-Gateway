import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);

test("gateway chat and dashboard are wired to the real backend", async () => {
  const [page, gateway, dashboardPage, dashboard, backend, hosting] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/SecureGatewayChat.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/dashboard/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../AuditDashboard.tsx", import.meta.url), "utf8"),
    readFile(new URL("../python_gateway/app.py", import.meta.url), "utf8"),
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /<SecureGatewayChat \/>/);
  assert.match(gateway, /\/gateway\/chat/);
  assert.match(gateway, /Detection & Risk Analysis/);
  assert.match(gateway, /Dark Mode/);
  assert.match(gateway, /componentPlaceholders/);
  assert.match(gateway, /apiErrorMessage\(payload\??\.detail, "Gateway request failed"\)/);
  assert.match(gateway, /\/health/);
  assert.doesNotMatch(gateway, /"Yesterday"|"May 16"|<strong>Secure<\/strong>/);
  assert.doesNotMatch(gateway, /localStorage\.setItem\([^)]*prompt/i);
  assert.match(gateway, /Open Security Dashboard/);
  assert.doesNotMatch(gateway, /Gateway ready|Component 01 detection active|Component 02\/03 extension points prepared/);
  assert.doesNotMatch(gateway, /View All/);
  assert.match(dashboardPage, /<AuditDashboard \/>/);
  assert.match(dashboard, /API_BASE_URL/);
  assert.match(dashboard, /apiFetch<AuditResponse>\("\/audit"\)/);
  assert.match(dashboard, /\/inspect/);
  assert.match(dashboard, /\/reports\/export/);
  assert.match(dashboard, /API_BASE_URL/);
  assert.match(dashboard, /TOKEN_KEY/);
  assert.doesNotMatch(dashboard, /Ingest Test Event|dashboard-live-ingest|sk-proj-demo-secret-value/);
  assert.match(dashboard, /No records in the backend yet/);
  assert.match(dashboard, /Prompt Monitor/);
  assert.match(dashboard, /setActiveView/);
  assert.match(dashboard, /window\.location\.assign\("\/audit-logs"\)/);
  assert.match(dashboard, /window\.location\.assign\("\/system-settings"\)/);
  assert.match(dashboard, /window\.location\.assign\("\/admin"\)/);
  assert.doesNotMatch(dashboard, /12,842|john\.doe@company\.com|API key detected in prompt/i);
  assert.match(dashboard, /totals\.sensitive/);
  await assert.rejects(access(new URL("security-dashboard-data.ts", templateRoot)));

  assert.match(backend, /DB_PATH = Path\(os\.getenv\("DB_PATH", str\(BASE_DIR \/ "audit_logs\.sqlite3"\)\)\)/);
  assert.match(backend, /CORS_ALLOWED_ORIGINS/);
  assert.match(backend, /validate_runtime_config/);
  assert.match(backend, /security_headers/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS audit_events/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS users/);
  assert.match(backend, /OLLAMA_MODEL = os\.getenv\("OLLAMA_MODEL", "qwen2\.5:3b"\)/);
  assert.match(backend, /@app\.post\("\/gateway\/chat"/);
  assert.match(backend, /redact_from_detection/);
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
  assert.match(authForm, /apiErrorMessage\(payload\.detail, "Authentication failed"\)/);
  assert.match(api, /function apiErrorMessage/);
  assert.match(api, /http:\/\/localhost:8000/);
});

test("dashboard chart layout uses responsive grids", async () => {
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");

  assert.match(css, /\.metrics-grid\s*\{[\s\S]*repeat\(auto-fit, minmax\(min\(100%, 10\.5rem\), 1fr\)\)/);
  assert.match(css, /\.content-grid\s*\{[\s\S]*grid-template-columns: repeat\(12, minmax\(0, 1fr\)\)/);
  assert.match(css, /\.content-grid\s*\{[\s\S]*align-items: start/);
  assert.match(css, /\.donut-layout\s*\{[\s\S]*grid-template-columns: max-content minmax\(8rem, 14rem\)/);
  assert.match(css, /\.donut-layout\s*\{[\s\S]*justify-content: start/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.donut-layout\s*\{[\s\S]*grid-template-columns: 1fr/);
  assert.match(css, /\.gateway-shell \.risk-panel\s*\{[\s\S]*padding: 1\.35rem 1rem/);
  assert.doesNotMatch(css, /\.gateway-sidebar,\s*\.risk-panel\s*\{/);
  assert.doesNotMatch(css, /grid-template-columns: minmax\(24rem, 1\.6fr\) minmax\(20rem, 0\.95fr\) minmax\(18rem, 0\.8fr\)/);
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
