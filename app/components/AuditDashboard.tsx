"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders, getStoredToken } from "../lib/api";

type Row = Record<string, string | number | boolean | null>;

type AuditResponse = {
  generatedAt: string;
  totals?: {
    total?: number;
    blocked?: number;
    highRisk?: number;
    activeUsers?: number;
    averageRiskScore?: number;
  };
  categories?: Row[];
  risks?: Row[];
  services?: Row[];
  topUsers?: Row[];
  recentEvents?: Row[];
  recentAlerts?: Row[];
  dataTypes?: Row[];
};

type ViewName =
  | "Dashboard"
  | "Prompt Monitor"
  | "Risk Alerts"
  | "Data Detection"
  | "Policy & Rules"
  | "Users & Access"
  | "Audit Logs"
  | "Reports"
  | "Integrations"
  | "System Settings"
  | "Admin Panel";

const navItems: ViewName[] = [
  "Dashboard",
  "Prompt Monitor",
  "Risk Alerts",
  "Data Detection",
  "Policy & Rules",
  "Users & Access",
  "Audit Logs",
  "Reports",
  "Integrations",
  "System Settings",
];

const categoryColors = ["#2f7df6", "#ef3748", "#f7a717", "#8557e8", "#35b86b"];

function number(value: unknown) {
  return Number(value ?? 0);
}

function displayNumber(value: unknown) {
  return number(value).toLocaleString("en-US");
}

function EmptyState({ message = "No records in the backend yet." }: { message?: string }) {
  return (
    <div className="empty-state">
      <strong>No data</strong>
      <p>{message}</p>
    </div>
  );
}

function Donut({ items, center }: { items: Row[]; center: string }) {
  const total = items.reduce((sum, item) => sum + number(item.value), 0);
  let cursor = 0;
  const stops = total
    ? items
        .map((item, index) => {
          const start = cursor;
          const end = cursor + (number(item.value) / total) * 100;
          cursor = end;
          return `${categoryColors[index % categoryColors.length]} ${start}% ${end}%`;
        })
        .join(", ")
    : "#1d2d45 0% 100%";

  return (
    <div className="donut" style={{ background: `conic-gradient(${stops})` }}>
      <div>
        <strong>{center}</strong>
        <span>Total</span>
      </div>
    </div>
  );
}

export function AuditDashboard() {
  const [activeView, setActiveView] = useState<ViewName>("Dashboard");
  const [data, setData] = useState<AuditResponse | null>(null);
  const [users, setUsers] = useState<Row[]>([]);
  const [policies, setPolicies] = useState<Row[]>([]);
  const [integrations, setIntegrations] = useState<Row[]>([]);
  const [health, setHealth] = useState<Row | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [posting, setPosting] = useState(false);
  const [prompt, setPrompt] = useState("");
  const [service, setService] = useState("ChatGPT Enterprise");
  const [inspectResult, setInspectResult] = useState<Row | null>(null);
  const [user, setUser] = useState<{ name: string; email: string; role: string } | null>(null);

  async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
    const token = getStoredToken();
    if (!token) {
      window.location.href = "/login";
      throw new Error("Login required");
    }

    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        ...authHeaders(token),
        ...(init?.headers ?? {}),
      },
    });
    const contentType = response.headers.get("content-type") ?? "";
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();

    if (response.status === 401) {
      window.localStorage.removeItem(TOKEN_KEY);
      window.location.href = "/login";
      throw new Error("Login expired");
    }
    if (!response.ok) {
      const detail = typeof payload === "object" && payload && "detail" in payload ? String(payload.detail) : "Backend request failed";
      throw new Error(detail);
    }
    return payload as T;
  }

  async function load() {
    try {
      const [audit, usersPayload, policyPayload, integrationPayload, healthPayload] = await Promise.all([
        apiFetch<AuditResponse>("/audit"),
        apiFetch<{ users: Row[] }>("/users").catch(() => ({ users: [] })),
        apiFetch<{ policies: Row[] }>("/policies").catch(() => ({ policies: [] })),
        apiFetch<{ integrations: Row[] }>("/integrations").catch(() => ({ integrations: [] })),
        fetch(`${API_BASE_URL}/health`).then((response) => response.json() as Promise<Row>),
      ]);
      setData(audit);
      setUsers(usersPayload.users);
      setPolicies(policyPayload.policies);
      setIntegrations(integrationPayload.integrations);
      setHealth(healthPayload);
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Backend request failed");
    }
  }

  useEffect(() => {
    const rawUser = window.localStorage.getItem(USER_KEY);
    if (rawUser) {
      setUser(JSON.parse(rawUser) as { name: string; email: string; role: string });
    }
    void load();
    const timer = window.setInterval(load, 15000);
    return () => window.clearInterval(timer);
  }, []);

  function logout() {
    window.localStorage.removeItem(TOKEN_KEY);
    window.localStorage.removeItem(USER_KEY);
    window.location.href = "/login";
  }

  async function inspectPrompt(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPosting(true);
    setNotice("");
    try {
      const result = await apiFetch<Row>("/inspect", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actor: user?.email ?? "local.user@company.com",
          department: "Security",
          service,
          prompt,
          source: "dashboard-prompt-monitor",
        }),
      });
      setInspectResult(result);
      setNotice("Prompt inspected, masked, and logged.");
      await load();
    } catch (inspectError) {
      setError(inspectError instanceof Error ? inspectError.message : "Prompt inspection failed");
    } finally {
      setPosting(false);
    }
  }

  async function exportReport() {
    try {
      const token = getStoredToken();
      const response = await fetch(`${API_BASE_URL}/reports/export`, { headers: authHeaders(token) });
      if (!response.ok) throw new Error("Report export failed");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "secure-ai-audit-report.csv";
      link.click();
      window.URL.revokeObjectURL(url);
      setNotice("CSV report downloaded.");
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : "Report export failed");
    }
  }

  const totals = data?.totals ?? {};
  const totalEvents = number(totals.total);
  const categories = data?.categories ?? [];
  const risks = data?.risks ?? [];
  const events = data?.recentEvents ?? [];
  const topUsers = data?.topUsers ?? [];
  const alerts = data?.recentAlerts ?? [];
  const dataTypes = data?.dataTypes ?? [];
  const services = data?.services ?? [];
  const maxType = Math.max(1, ...dataTypes.map((item) => number(item.value)));
  const maxBlocked = Math.max(1, ...topUsers.map((item) => number(item.blocked)));

  const metrics = useMemo(
    () => [
      { label: "Prompts Inspected", value: totalEvents, tone: "blue" },
      { label: "Blocked Prompts", value: totals.blocked ?? 0, tone: "red" },
      { label: "High Risk Events", value: totals.highRisk ?? 0, tone: "amber" },
      { label: "Sensitive Detections", value: totalEvents, tone: "violet" },
      { label: "Active Users", value: totals.activeUsers ?? 0, tone: "green" },
    ],
    [totalEvents, totals.activeUsers, totals.blocked, totals.highRisk],
  );

  const pageDescriptions: Record<ViewName, string> = {
    Dashboard: "Live security metrics from the local FastAPI backend.",
    "Prompt Monitor": "Inspect prompts and mask sensitive data before AI submission.",
    "Risk Alerts": "High-risk and blocked prompt events.",
    "Data Detection": "Sensitive data categories and detected data types.",
    "Policy & Rules": "Enforced security policies used by the gateway.",
    "Users & Access": "Registered users and audit activity.",
    "Audit Logs": "Stored audit records with masked output.",
    Reports: "Export compliance-ready CSV reports.",
    Integrations: "Configured AI service and extension integration status.",
    "System Settings": "Backend health and runtime configuration.",
    "Admin Panel": "Create users and assign admin, auditor, or user roles.",
  };

  const visibleNavItems = user?.role === "admin" ? [...navItems, "Admin Panel" as ViewName] : navItems;

  function openView(item: ViewName) {
    if (item === "Audit Logs") window.location.href = "/audit-logs";
    else if (item === "System Settings") window.location.href = "/system-settings";
    else if (item === "Admin Panel") window.location.href = "/admin";
    else setActiveView(item);
  }

  return (
    <main className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark">S</div>
          <div>
            <strong>Secure AI</strong>
            <span>Prompt Gateway</span>
          </div>
        </div>

        <nav aria-label="Primary navigation">
          {visibleNavItems.map((item) => (
            <button type="button" className={item === activeView ? "active" : ""} key={item} onClick={() => openView(item)}>
              <span className="nav-dot" />
              {item}
            </button>
          ))}
        </nav>

        <section className="system-card" aria-labelledby="system-status-title">
          <p id="system-status-title">System Status</p>
          <strong>{error ? "Degraded" : "Healthy"}</strong>
          <span>{error || `FastAPI connected at ${API_BASE_URL}`}</span>
          <button type="button" onClick={() => { window.location.href = "/system-settings"; }}>View System Health</button>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p>Secure AI Prompt Gateway</p>
            <h1>{activeView}</h1>
            <span>{pageDescriptions[activeView]}</span>
          </div>
          <div className="topbar-actions" aria-label="Dashboard controls">
            <button type="button" onClick={() => void load()}>Refresh</button>
            <button type="button" onClick={() => void exportReport()}>Export CSV</button>
            <div className="admin-chip">
              <span />
              <div>
                <strong>{user?.name ?? "sec.admin"}</strong>
                <small>{user?.email ?? "Security Admin"}</small>
              </div>
            </div>
            <button type="button" onClick={logout}>Logout</button>
          </div>
        </header>

        {error ? <div className="backend-error">{error}</div> : null}
        {notice ? <div className="success-state">{notice}</div> : null}

        {activeView === "Dashboard" ? (
          <>
            <Metrics metrics={metrics} />
            <section className="content-grid">
              <CategoryPanel categories={categories} totalEvents={totalEvents} />
              <AlertsPanel alerts={alerts} />
              <RiskPanel risks={risks} totalEvents={totalEvents} />
              <UsersPanel users={topUsers} maxBlocked={maxBlocked} />
              <SourcesPanel services={services} />
              <DataTypesPanel dataTypes={dataTypes} maxType={maxType} />
              <AuditTable events={events} onReload={load} />
            </section>
          </>
        ) : null}

        {activeView === "Prompt Monitor" ? (
          <section className="single-view">
            <article className="panel tool-panel">
              <div className="panel-heading">
                <div>
                  <h2>Prompt Monitor</h2>
                  <p>Submit a prompt to FastAPI for detection, masking, risk scoring, and audit logging.</p>
                </div>
              </div>
              <form className="prompt-form" onSubmit={inspectPrompt}>
                <label>
                  AI Service
                  <select value={service} onChange={(event) => setService(event.target.value)}>
                    <option>ChatGPT Enterprise</option>
                    <option>Google Gemini</option>
                    <option>Microsoft Copilot</option>
                    <option>Claude</option>
                  </select>
                </label>
                <label>
                  Prompt
                  <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Paste a prompt with an API key, password, email, phone number, card number, or source code." required />
                </label>
                <button type="submit" disabled={posting}>{posting ? "Inspecting..." : "Inspect & Log Prompt"}</button>
              </form>
              {inspectResult ? (
                <div className="result-box">
                  <strong>{String(inspectResult.status)} - {String(inspectResult.risk)} Risk</strong>
                  <p>{String(inspectResult.finding)} detected by {String(inspectResult.policyRule)}</p>
                  <pre>{String(inspectResult.maskedOutput)}</pre>
                </div>
              ) : null}
            </article>
          </section>
        ) : null}

        {activeView === "Risk Alerts" ? <section className="single-view"><AlertsPanel alerts={alerts} /></section> : null}
        {activeView === "Data Detection" ? <section className="content-grid"><CategoryPanel categories={categories} totalEvents={totalEvents} /><DataTypesPanel dataTypes={dataTypes} maxType={maxType} /></section> : null}
        {activeView === "Policy & Rules" ? <PolicyPanel policies={policies} /> : null}
        {activeView === "Users & Access" ? <UsersAccessPanel users={users} /> : null}
        {activeView === "Reports" ? <ReportsPanel totalEvents={totalEvents} onExport={exportReport} /> : null}
        {activeView === "Integrations" ? <IntegrationsPanel integrations={integrations} /> : null}
      </section>
    </main>
  );
}

function Metrics({ metrics }: { metrics: Array<{ label: string; value: unknown; tone: string }> }) {
  return (
    <section className="metrics-grid" aria-label="Security metrics">
      {metrics.map((card) => (
        <article className={`panel metric metric-${card.tone}`} key={card.label}>
          <div className="metric-icon">{card.label.charAt(0)}</div>
          <div>
            <p>{card.label}</p>
            <strong>{displayNumber(card.value)}</strong>
            <span>live backend value</span>
          </div>
        </article>
      ))}
    </section>
  );
}

function CategoryPanel({ categories, totalEvents }: { categories: Row[]; totalEvents: number }) {
  return (
    <article className="panel category-panel">
      <div className="panel-heading"><div><h2>Detections by Category</h2><p>Read from stored audit events</p></div></div>
      {categories.length ? (
        <div className="donut-layout">
          <Donut items={categories} center={displayNumber(totalEvents)} />
          <div className="category-list">
            {categories.map((item, index) => (
              <div key={String(item.name)}>
                <span style={{ background: categoryColors[index % categoryColors.length] }} />
                <p>{item.name}</p>
                <strong>{displayNumber(item.value)}</strong>
              </div>
            ))}
          </div>
        </div>
      ) : <EmptyState message="Inspect a prompt to populate sensitive data categories." />}
    </article>
  );
}

function AlertsPanel({ alerts }: { alerts: Row[] }) {
  return (
    <article className="panel alerts-panel">
      <div className="panel-heading"><div><h2>Recent High Risk Alerts</h2><p>Blocked or high-risk database records</p></div></div>
      <div className="alert-list">
        {alerts.length ? alerts.map((alert) => (
          <div className={`alert ${String(alert.risk).toLowerCase()}`} key={String(alert.id)}>
            <span>{String(alert.risk ?? "R").charAt(0)}</span>
            <div>
              <strong>{alert.finding}</strong>
              <p>{alert.actor}</p>
              <small>{alert.service} - {alert.timestamp}</small>
            </div>
            <em>{alert.risk}</em>
          </div>
        )) : <EmptyState message="No high-risk alerts yet." />}
      </div>
    </article>
  );
}

function RiskPanel({ risks, totalEvents }: { risks: Row[]; totalEvents: number }) {
  return (
    <article className="panel risk-panel">
      <div className="panel-heading"><div><h2>Risk Level Distribution</h2><p>Grouped directly by backend risk field</p></div></div>
      <div className="donut-layout compact">
        <Donut items={risks} center={displayNumber(totalEvents)} />
        <div className="category-list">
          {risks.length ? risks.map((item, index) => (
            <div key={String(item.name)}>
              <span style={{ background: categoryColors[index % categoryColors.length] }} />
              <p>{item.name}</p>
              <strong>{displayNumber(item.value)}</strong>
            </div>
          )) : <EmptyState />}
        </div>
      </div>
    </article>
  );
}

function UsersPanel({ users, maxBlocked }: { users: Row[]; maxBlocked: number }) {
  return (
    <article className="panel users-panel">
      <div className="panel-heading"><div><h2>Top Users by Blocked Prompts</h2><p>Calculated from real blocked events</p></div></div>
      <div className="rank-list">
        {users.length ? users.map((user, index) => (
          <div key={String(user.name)}>
            <span>{index + 1}</span>
            <p>{user.name}<small>{user.department}</small></p>
            <strong>{displayNumber(user.blocked)}</strong>
            <i style={{ width: `${(number(user.blocked) / maxBlocked) * 100}%` }} />
          </div>
        )) : <EmptyState />}
      </div>
    </article>
  );
}

function SourcesPanel({ services }: { services: Row[] }) {
  return (
    <article className="panel performance-panel">
      <div className="panel-heading"><div><h2>Backend Sources</h2><p>Services writing audit events</p></div></div>
      <dl>
        {services.length ? services.map((service) => (
          <div key={String(service.name)}><dt>{service.name}</dt><dd>{displayNumber(service.value)}</dd></div>
        )) : <div><dt>No services yet</dt><dd>0</dd></div>}
      </dl>
    </article>
  );
}

function DataTypesPanel({ dataTypes, maxType }: { dataTypes: Row[]; maxType: number }) {
  return (
    <article className="panel types-panel">
      <div className="panel-heading"><div><h2>Top Detected Data Types</h2><p>Grouped by stored finding name</p></div></div>
      <div className="data-type-list">
        {dataTypes.length ? dataTypes.map((item) => (
          <div key={String(item.name)}>
            <p>{item.name}<strong>{displayNumber(item.value)}</strong></p>
            <span><i style={{ width: `${(number(item.value) / maxType) * 100}%` }} /></span>
          </div>
        )) : <EmptyState />}
      </div>
    </article>
  );
}

function AuditTable({ events, onReload }: { events: Row[]; onReload: () => Promise<void> }) {
  return (
    <article className="panel audit-panel">
      <div className="panel-heading">
        <div><h2>Audit Logs</h2><p>Records loaded from FastAPI SQLite, with masked output only</p></div>
        <button type="button" onClick={() => void onReload()}>Reload Logs</button>
      </div>
      <div className="audit-table" role="table" aria-label="Audit log events">
        <div role="row" className="audit-header"><span>Event ID</span><span>Time</span><span>User</span><span>Action</span><span>Finding</span><span>Masked Output</span><span>Status</span></div>
        {events.length ? events.map((event) => (
          <div role="row" className="audit-row" key={String(event.id)}>
            <span>{event.id}</span><span>{event.timestamp}</span><span>{event.actor}</span><span>{event.action}</span>
            <span><em className={`risk-badge ${String(event.risk).toLowerCase()}`}>{event.finding}</em></span>
            <span>{event.maskedOutput}</span><span>{event.status}</span>
          </div>
        )) : <div className="audit-row"><span>No records</span><span /><span /><span /><span /><span>Backend is ready for audit ingestion.</span><span /></div>}
      </div>
    </article>
  );
}

function PolicyPanel({ policies }: { policies: Row[] }) {
  return (
    <section className="single-view">
      <article className="panel policy-panel">
        <div className="panel-heading"><div><h2>Security Policy & Access Control Engine</h2><p>FastAPI exposes active local gateway policies.</p></div></div>
        <div className="policy-grid">
          {policies.map((policy) => (
            <div key={String(policy.name)}><strong>{policy.name}</strong><p>{policy.owner} owner</p><span>{policy.mode}</span><em>{policy.enabled ? "Enabled" : "Disabled"}</em></div>
          ))}
        </div>
      </article>
    </section>
  );
}

function UsersAccessPanel({ users }: { users: Row[] }) {
  return (
    <section className="single-view">
      <article className="panel audit-panel">
        <div className="panel-heading"><div><h2>Users & Access</h2><p>Registered FastAPI local users and activity counts.</p></div></div>
        <div className="simple-table">
          <div><strong>Name</strong><strong>Email</strong><strong>Role</strong><strong>Prompts</strong><strong>Blocked</strong></div>
          {users.map((item) => <div key={String(item.email)}><span>{item.name}</span><span>{item.email}</span><span>{item.role}</span><span>{displayNumber(item.promptCount)}</span><span>{displayNumber(item.blockedCount)}</span></div>)}
        </div>
      </article>
    </section>
  );
}

function ReportsPanel({ totalEvents, onExport }: { totalEvents: number; onExport: () => Promise<void> }) {
  return (
    <section className="single-view">
      <article className="panel tool-panel">
        <div className="panel-heading"><div><h2>Reports</h2><p>Download a CSV audit report from FastAPI.</p></div></div>
        <div className="action-card"><strong>{displayNumber(totalEvents)} audit events available</strong><p>Export includes event id, user, service, action, status, risk, finding, category, policy, masked output, and source.</p><button type="button" onClick={() => void onExport()}>Download CSV Report</button></div>
      </article>
    </section>
  );
}

function IntegrationsPanel({ integrations }: { integrations: Row[] }) {
  return (
    <section className="single-view">
      <article className="panel audit-panel">
        <div className="panel-heading"><div><h2>Integrations</h2><p>Local integration readiness for AI services and browser extension.</p></div></div>
        <div className="policy-grid">{integrations.map((item) => <div key={String(item.name)}><strong>{item.name}</strong><p>{item.mode}</p><span>{item.status}</span></div>)}</div>
      </article>
    </section>
  );
}

function SettingsPanel({ health }: { health: Row | null }) {
  return (
    <section className="single-view">
      <article className="panel tool-panel">
        <div className="panel-heading"><div><h2>System Settings</h2><p>Local FastAPI backend status.</p></div></div>
        <div className="settings-grid">
          <div><strong>Backend URL</strong><span>{API_BASE_URL}</span></div>
          <div><strong>Status</strong><span>{String(health?.status ?? "Unknown")}</span></div>
          <div><strong>Service</strong><span>{String(health?.service ?? "Unknown")}</span></div>
          <div><strong>Database</strong><span>{String(health?.database ?? "Unknown")}</span></div>
        </div>
      </article>
    </section>
  );
}
