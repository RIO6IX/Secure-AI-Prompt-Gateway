"use client";

import { useEffect, useMemo, useState } from "react";

type Row = Record<string, string | number | null>;

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
  trend?: Row[];
};

const navItems = [
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

function EmptyState() {
  return (
    <div className="empty-state">
      <strong>No audit events in the backend yet</strong>
      <p>
        Send events from the Python gateway, browser extension, or the live ingest button.
        The dashboard will update from the database.
      </p>
    </div>
  );
}

export function AuditDashboard() {
  const [data, setData] = useState<AuditResponse | null>(null);
  const [error, setError] = useState("");
  const [posting, setPosting] = useState(false);

  async function load() {
    try {
      const response = await fetch("/api/audit", { cache: "no-store" });
      const payload = (await response.json()) as AuditResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Audit backend failed");
      setData(payload);
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Audit backend failed");
    }
  }

  useEffect(() => {
    void load();
    const timer = window.setInterval(load, 15000);
    return () => window.clearInterval(timer);
  }, []);

  async function ingestSampleEvent() {
    setPosting(true);
    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actor: "security.demo@company.com",
          department: "Security",
          service: "ChatGPT Enterprise",
          action: "Prompt blocked",
          status: "Blocked",
          risk: "High",
          riskScore: 92,
          finding: "API Key",
          category: "Credentials & Secrets",
          policyRule: "Block credentials and tokens",
          maskedOutput: "sk-proj-********************************",
          originalPrompt: "Deploy using sk-proj-demo-secret-value",
          source: "dashboard-live-ingest",
        }),
      });
      if (!response.ok) throw new Error("Event write failed");
      await load();
    } catch (postError) {
      setError(postError instanceof Error ? postError.message : "Event write failed");
    } finally {
      setPosting(false);
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
          {navItems.map((item) => (
            <a href={`#${item.toLowerCase().replaceAll(" ", "-").replace("&", "and")}`} className={item === "Dashboard" ? "active" : ""} key={item}>
              <span className="nav-dot" />
              {item}
            </a>
          ))}
        </nav>

        <section className="system-card" aria-labelledby="system-status-title">
          <p id="system-status-title">System Status</p>
          <strong>{error ? "Degraded" : "Healthy"}</strong>
          <span>{error || "Connected to audit backend"}</span>
          <a href="/api/health">View System Health</a>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p>Secure AI Prompt Gateway</p>
            <h1>Security Dashboard</h1>
            <span>Live audit records from the backend database, refreshed every 15 seconds.</span>
          </div>
          <div className="topbar-actions" aria-label="Dashboard controls">
            <button type="button" onClick={() => void load()}>Refresh</button>
            <button type="button" onClick={() => void ingestSampleEvent()} disabled={posting}>
              {posting ? "Writing..." : "Ingest Test Event"}
            </button>
            <div className="admin-chip">
              <span />
              <div>
                <strong>sec.admin</strong>
                <small>Security Admin</small>
              </div>
            </div>
          </div>
        </header>

        {error ? <div className="backend-error">{error}</div> : null}

        <section className="metrics-grid" id="dashboard" aria-label="Security metrics">
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

        {!data ? <EmptyState /> : null}

        <section className="content-grid">
          <article className="panel category-panel" id="data-detection">
            <div className="panel-heading">
              <div>
                <h2>Detections by Category</h2>
                <p>Read from stored audit events</p>
              </div>
            </div>
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
            ) : <EmptyState />}
          </article>

          <article className="panel alerts-panel" id="risk-alerts">
            <div className="panel-heading">
              <div>
                <h2>Recent High Risk Alerts</h2>
                <p>Blocked or high-risk database records</p>
              </div>
            </div>
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
              )) : <EmptyState />}
            </div>
          </article>

          <article className="panel risk-panel">
            <div className="panel-heading">
              <div>
                <h2>Risk Level Distribution</h2>
                <p>Grouped directly by backend risk field</p>
              </div>
            </div>
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

          <article className="panel users-panel" id="users-and-access">
            <div className="panel-heading">
              <div>
                <h2>Top Users by Blocked Prompts</h2>
                <p>Calculated from real blocked events</p>
              </div>
            </div>
            <div className="rank-list">
              {topUsers.length ? topUsers.map((user, index) => (
                <div key={String(user.name)}>
                  <span>{index + 1}</span>
                  <p>{user.name}<small>{user.department}</small></p>
                  <strong>{displayNumber(user.blocked)}</strong>
                  <i style={{ width: `${(number(user.blocked) / maxBlocked) * 100}%` }} />
                </div>
              )) : <EmptyState />}
            </div>
          </article>

          <article className="panel performance-panel" id="system-settings">
            <div className="panel-heading">
              <div>
                <h2>Backend Sources</h2>
                <p>Services writing audit events</p>
              </div>
            </div>
            <dl>
              {services.length ? services.map((service) => (
                <div key={String(service.name)}>
                  <dt>{service.name}</dt>
                  <dd>{displayNumber(service.value)}</dd>
                </div>
              )) : (
                <div>
                  <dt>No services yet</dt>
                  <dd>0</dd>
                </div>
              )}
            </dl>
          </article>

          <article className="panel types-panel">
            <div className="panel-heading">
              <div>
                <h2>Top Detected Data Types</h2>
                <p>Grouped by stored finding name</p>
              </div>
            </div>
            <div className="data-type-list">
              {dataTypes.length ? dataTypes.map((item) => (
                <div key={String(item.name)}>
                  <p>{item.name}<strong>{displayNumber(item.value)}</strong></p>
                  <span><i style={{ width: `${(number(item.value) / maxType) * 100}%` }} /></span>
                </div>
              )) : <EmptyState />}
            </div>
          </article>

          <article className="panel audit-panel" id="audit-logs">
            <div className="panel-heading">
              <div>
                <h2>Audit Logs</h2>
                <p>Records loaded from D1, with masked output only</p>
              </div>
              <button type="button" onClick={() => void load()}>Reload Logs</button>
            </div>
            <div className="audit-table" role="table" aria-label="Audit log events">
              <div role="row" className="audit-header">
                <span>Event ID</span>
                <span>Time</span>
                <span>User</span>
                <span>Action</span>
                <span>Finding</span>
                <span>Masked Output</span>
                <span>Status</span>
              </div>
              {events.length ? events.map((event) => (
                <div role="row" className="audit-row" key={String(event.id)}>
                  <span>{event.id}</span>
                  <span>{event.timestamp}</span>
                  <span>{event.actor}</span>
                  <span>{event.action}</span>
                  <span><em className={`risk-badge ${String(event.risk).toLowerCase()}`}>{event.finding}</em></span>
                  <span>{event.maskedOutput}</span>
                  <span>{event.status}</span>
                </div>
              )) : (
                <div className="audit-row">
                  <span>No records</span>
                  <span />
                  <span />
                  <span />
                  <span />
                  <span>Backend is ready for audit ingestion.</span>
                  <span />
                </div>
              )}
            </div>
          </article>
        </section>
      </section>
    </main>
  );
}
