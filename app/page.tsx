import type { Metadata } from "next";
import {
  auditEvents,
  categoryBreakdown,
  dataTypes,
  highRiskAlerts,
  metricCards,
  policyRules,
  riskDistribution,
  systemHealth,
  topUsers,
  trendDays,
  trendSeries,
} from "./lib/security-dashboard-data";

export const metadata: Metadata = {
  title: "Secure AI Prompt Gateway Dashboard",
  description:
    "Audit logging and security monitoring dashboard for sensitive prompt leakage prevention.",
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

function compactNumber(value: number) {
  return value.toLocaleString("en-US");
}

function Donut({
  items,
  center,
}: {
  items: Array<{ value: number; color: string }>;
  center: string;
}) {
  let cursor = 0;
  const total = items.reduce((sum, item) => sum + item.value, 0);
  const stops = items
    .map((item) => {
      const start = cursor;
      const end = cursor + (item.value / total) * 100;
      cursor = end;
      return `${item.color} ${start}% ${end}%`;
    })
    .join(", ");

  return (
    <div className="donut" style={{ background: `conic-gradient(${stops})` }}>
      <div>
        <strong>{center}</strong>
        <span>Total</span>
      </div>
    </div>
  );
}

function MiniBars({ values, tone }: { values: number[]; tone: string }) {
  const max = Math.max(...values);

  return (
    <div className={`mini-bars ${tone}`} aria-hidden="true">
      {values.map((value, index) => (
        <span
          key={`${value}-${index}`}
          style={{ height: `${Math.max(18, (value / max) * 46)}px` }}
        />
      ))}
    </div>
  );
}

export default function Home() {
  const totalDetections = categoryBreakdown.reduce((sum, item) => sum + item.value, 0);
  const maxTrend = Math.max(...trendSeries.flatMap((series) => series.values));
  const maxDataType = Math.max(...dataTypes.map((item) => item.value));
  const maxUserBlocks = Math.max(...topUsers.map((user) => user.blocked));

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
          <strong>Healthy</strong>
          <span>All services operational</span>
          <a href="#system-settings">View System Health</a>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p>Secure AI Prompt Gateway</p>
            <h1>Security Dashboard</h1>
            <span>Real-time audit logging for prompts, threats, risk decisions, and system activity.</span>
          </div>
          <div className="topbar-actions" aria-label="Dashboard controls">
            <button type="button">Last 7 Days</button>
            <button type="button">Export CSV</button>
            <div className="admin-chip">
              <span />
              <div>
                <strong>sec.admin</strong>
                <small>Security Admin</small>
              </div>
            </div>
          </div>
        </header>

        <section className="metrics-grid" id="dashboard" aria-label="Security metrics">
          {metricCards.map((card) => (
            <article className={`panel metric metric-${card.tone}`} key={card.label}>
              <div className="metric-icon">{card.label.charAt(0)}</div>
              <div>
                <p>{card.label}</p>
                <strong>{card.value}</strong>
                <span>{card.delta} vs last 7 days</span>
              </div>
              <MiniBars values={[16, 23, 18, 31, 21, 36, 24, 41, 28, 45, 37, 52]} tone={card.tone} />
            </article>
          ))}
        </section>

        <section className="content-grid">
          <article className="panel trend-panel" id="data-detection">
            <div className="panel-heading">
              <div>
                <h2>Detections Over Time</h2>
                <p>Classified prompt findings by sensitive data type</p>
              </div>
              <button type="button">Daily</button>
            </div>
            <div className="legend">
              {trendSeries.map((series) => (
                <span className={series.color} key={series.label}>{series.label}</span>
              ))}
            </div>
            <div className="bar-chart" aria-label="Detections over the last seven days">
              {trendDays.map((day, dayIndex) => (
                <div className="bar-group" key={day}>
                  <div className="stack">
                    {trendSeries.map((series) => (
                      <span
                        className={series.color}
                        key={series.label}
                        title={`${series.label}: ${series.values[dayIndex]}`}
                        style={{ height: `${(series.values[dayIndex] / maxTrend) * 100}%` }}
                      />
                    ))}
                  </div>
                  <small>{day}</small>
                </div>
              ))}
            </div>
          </article>

          <article className="panel category-panel">
            <div className="panel-heading">
              <div>
                <h2>Detections by Category</h2>
                <p>All-time sensitive data classifications</p>
              </div>
            </div>
            <div className="donut-layout">
              <Donut items={categoryBreakdown} center={compactNumber(totalDetections)} />
              <div className="category-list">
                {categoryBreakdown.map((item) => (
                  <div key={item.name}>
                    <span style={{ background: item.color }} />
                    <p>{item.name}</p>
                    <strong>{compactNumber(item.value)}</strong>
                    <small>{item.percent}%</small>
                  </div>
                ))}
              </div>
            </div>
          </article>

          <article className="panel alerts-panel" id="risk-alerts">
            <div className="panel-heading">
              <div>
                <h2>Recent High Risk Alerts</h2>
                <p>Escalations needing security review</p>
              </div>
              <a href="#audit-logs">View All</a>
            </div>
            <div className="alert-list">
              {highRiskAlerts.map((alert) => (
                <div className={`alert ${alert.level.toLowerCase()}`} key={`${alert.title}-${alert.time}`}>
                  <span>{alert.level.charAt(0)}</span>
                  <div>
                    <strong>{alert.title}</strong>
                    <p>{alert.user}</p>
                    <small>{alert.service} - {alert.time}</small>
                  </div>
                  <em>{alert.level}</em>
                </div>
              ))}
            </div>
          </article>

          <article className="panel risk-panel">
            <div className="panel-heading">
              <div>
                <h2>Risk Level Distribution</h2>
                <p>Gateway decision outcomes</p>
              </div>
            </div>
            <div className="donut-layout compact">
              <Donut items={riskDistribution} center="12,842" />
              <div className="category-list">
                {riskDistribution.map((item) => (
                  <div key={item.name}>
                    <span style={{ background: item.color }} />
                    <p>{item.name}</p>
                    <strong>{compactNumber(item.value)}</strong>
                    <small>{item.percent}%</small>
                  </div>
                ))}
              </div>
            </div>
          </article>

          <article className="panel users-panel" id="users-and-access">
            <div className="panel-heading">
              <div>
                <h2>Top Users by Blocked Prompts</h2>
                <p>Useful for coaching and access reviews</p>
              </div>
            </div>
            <div className="rank-list">
              {topUsers.map((user, index) => (
                <div key={user.name}>
                  <span>{index + 1}</span>
                  <p>{user.name}<small>{user.department}</small></p>
                  <strong>{user.blocked}</strong>
                  <i style={{ width: `${(user.blocked / maxUserBlocks) * 100}%` }} />
                </div>
              ))}
            </div>
          </article>

          <article className="panel performance-panel" id="system-settings">
            <div className="panel-heading">
              <div>
                <h2>System Performance</h2>
                <p>Current load and audit pipeline status</p>
              </div>
            </div>
            <dl>
              <div>
                <dt>Avg. Response Time</dt>
                <dd>286 ms</dd>
              </div>
              {systemHealth.map((item) => (
                <div className="health-row" key={item.name}>
                  <dt>{item.name}</dt>
                  <dd>{item.value}%</dd>
                  <span style={{ width: `${item.value}%` }} />
                </div>
              ))}
              <div>
                <dt>Uptime</dt>
                <dd>99.98%</dd>
              </div>
            </dl>
          </article>

          <article className="panel types-panel">
            <div className="panel-heading">
              <div>
                <h2>Top Detected Data Types</h2>
                <p>Masking candidates seen most often</p>
              </div>
            </div>
            <div className="data-type-list">
              {dataTypes.map((item) => (
                <div key={item.name}>
                  <p>{item.name}<strong>{compactNumber(item.value)}</strong></p>
                  <span><i style={{ width: `${(item.value / maxDataType) * 100}%` }} /></span>
                </div>
              ))}
            </div>
          </article>

          <article className="panel audit-panel" id="audit-logs">
            <div className="panel-heading">
              <div>
                <h2>Audit Logs</h2>
                <p>Tamper-aware record of prompt gateway decisions and masked values</p>
              </div>
              <button type="button">Download Report</button>
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
              {auditEvents.map((event) => (
                <div role="row" className="audit-row" key={event.id}>
                  <span>{event.id}</span>
                  <span>{event.timestamp}</span>
                  <span>{event.actor}</span>
                  <span>{event.action}</span>
                  <span><em className={`risk-badge ${event.risk.toLowerCase()}`}>{event.finding}</em></span>
                  <span>{event.sanitized}</span>
                  <span>{event.status}</span>
                </div>
              ))}
            </div>
          </article>

          <article className="panel policy-panel" id="policy-and-rules">
            <div className="panel-heading">
              <div>
                <h2>Security Policy & Access Control Activity</h2>
                <p>Rules connected to prompt masking, blocking, and monitoring</p>
              </div>
            </div>
            <div className="policy-grid">
              {policyRules.map((rule) => (
                <div key={rule.name}>
                  <strong>{rule.name}</strong>
                  <p>{rule.owner} owner</p>
                  <span>{rule.mode}</span>
                  <em>{compactNumber(rule.hits)} hits</em>
                </div>
              ))}
            </div>
          </article>
        </section>
      </section>
    </main>
  );
}
