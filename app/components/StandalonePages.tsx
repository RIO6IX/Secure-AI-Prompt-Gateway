"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders, getStoredToken } from "../lib/api";

type Role = "admin" | "auditor" | "user" | "approver";
type Row = Record<string, string | number | boolean | null>;

async function logout() {
  await fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", headers: authHeaders() }).catch(() => undefined);
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.location.href = "/login";
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
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
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    void logout();
    throw new Error("Login expired");
  }
  if (!response.ok) {
    throw new Error(String(payload.detail ?? "Backend request failed"));
  }
  return payload as T;
}

export function PageChrome({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  const [user, setUser] = useState<Row | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void apiFetch<Row>("/auth/me").then(setUser).catch(() => undefined);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  return (
    <main className="secure-admin-page">
      <header className="secure-admin-header">
        <div className="secure-brand">
          <span className="secure-shield small" aria-hidden="true">S</span>
          <div>
            <strong>Secure AI</strong>
            <small>Administration</small>
          </div>
        </div>
        <nav className="secure-admin-nav" aria-label="Page navigation">
          <Link href="/">Back to chat</Link>
          <Link className={title === "Security Controls" ? "active" : ""} href="/security">Security controls</Link>
          <Link className={title === "Privacy-safe audit dashboard" ? "active" : ""} href="/audit-logs">Audit logs</Link>
          <Link className={title === "System Settings" ? "active" : ""} href="/system-settings">System settings</Link>
          {user?.role === "admin" ? <Link className={title === "Admin Panel" ? "active" : ""} href="/admin">Users</Link> : null}
          <button type="button" onClick={() => void logout()}>Sign out</button>
        </nav>
      </header>
      <section className="secure-admin-content">
        <p className="secure-eyebrow">Administrator workspace</p>
        <h1>{title}</h1>
        <p className="secure-admin-description">{description}</p>
        {children}
      </section>
    </main>
  );
}

export function AuditLogsPage() {
  const [events, setEvents] = useState<Row[]>([]);
  const [error, setError] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 20;

  async function load() {
    try {
      const payload = await apiFetch<Row[]>("/audit/events");
      setEvents(payload);
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load audit logs");
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  const filteredEvents = useMemo(() => events.filter((event) => {
    const actorMatches = String(event.actor).toLowerCase().includes(userFilter.trim().toLowerCase());
    const decisionMatches = !decisionFilter || String(event.status).toLowerCase() === decisionFilter.toLowerCase();
    const riskMatches = !riskFilter || String(event.risk).toLowerCase() === riskFilter.toLowerCase();
    return actorMatches && decisionMatches && riskMatches;
  }), [events, userFilter, decisionFilter, riskFilter]);
  const visibleEvents = filteredEvents.slice(page * pageSize, (page + 1) * pageSize);
  const first = filteredEvents.length ? page * pageSize + 1 : 0;
  const last = Math.min((page + 1) * pageSize, filteredEvents.length);
  const count = (status: string) => filteredEvents.filter((event) => String(event.status).toLowerCase() === status).length;

  return (
    <PageChrome title="Privacy-safe audit dashboard" description="Security metadata only. Raw detected values and private credentials are not displayed.">
      {error ? <div className="backend-error">{error}</div> : null}
      <section className="secure-audit-metrics" aria-label="Audit summary">
        <div><small>Filtered events</small><strong>{filteredEvents.length}</strong></div>
        <div><small>Allowed</small><strong>{count("allowed")}</strong></div>
        <div><small>Sanitized</small><strong>{count("sanitized")}</strong></div>
        <div><small>Blocked</small><strong>{count("blocked")}</strong></div>
      </section>
      <article className="secure-audit-panel">
        <div className="secure-audit-title">
          <div><p className="secure-eyebrow">Security activity</p><h2>Audit events</h2></div>
          <button type="button" onClick={() => void load()}>Refresh</button>
        </div>
        <form className="secure-audit-filters" onSubmit={(event) => { event.preventDefault(); setPage(0); }}>
          <label>User<input value={userFilter} onChange={(event) => { setUserFilter(event.target.value); setPage(0); }} placeholder="All users" /></label>
          <label>Decision<select value={decisionFilter} onChange={(event) => { setDecisionFilter(event.target.value); setPage(0); }}><option value="">All decisions</option><option value="Allowed">Allowed</option><option value="Sanitized">Sanitized</option><option value="Blocked">Blocked</option></select></label>
          <label>Risk level<select value={riskFilter} onChange={(event) => { setRiskFilter(event.target.value); setPage(0); }}><option value="">All risk levels</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select></label>
          <button type="submit">Apply filters</button>
        </form>
        <div className="secure-table-wrap">
          <table>
            <thead><tr><th>Time</th><th>User</th><th>Decision</th><th>Risk</th><th>Category</th><th>Finding</th><th>Status</th></tr></thead>
            <tbody>{visibleEvents.map((event) => (
              <tr key={String(event.id)}>
                <td>{new Date(String(event.timestamp)).toLocaleString()}</td><td>{event.actor}</td><td>{event.action}</td>
                <td><span className={`secure-table-badge ${String(event.risk).toLowerCase()}`}>{event.risk}</span></td>
                <td>{event.category}</td><td>{event.finding}</td><td><span className={`secure-table-badge ${String(event.status).toLowerCase()}`}>{event.status}</span></td>
              </tr>
            ))}</tbody>
          </table>
          {visibleEvents.length === 0 ? <p className="secure-audit-empty">No audit events match these filters.</p> : null}
        </div>
        <div className="secure-pagination">
          <span>Showing {first}–{last} of {filteredEvents.length}</span>
          <div>
            <button type="button" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</button>
            <button type="button" disabled={last >= filteredEvents.length} onClick={() => setPage((current) => current + 1)}>Next</button>
          </div>
        </div>
      </article>
    </PageChrome>
  );
}

export function SystemSettingsPage() {
  const [health, setHealth] = useState<Row | null>(null);

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`).then((response) => response.json()).then((payload) => setHealth(payload as Row));
  }, []);

  return (
    <PageChrome title="System Settings" description="Separate system settings webpage for backend/runtime status.">
      <article className="panel tool-panel single-view">
        <div className="panel-heading"><div><h2>Runtime Status</h2><p>Local FastAPI backend configuration.</p></div></div>
        <div className="settings-grid">
          <div><strong>Backend URL</strong><span>{API_BASE_URL}</span></div>
          <div><strong>Status</strong><span>{String(health?.status ?? "Unknown")}</span></div>
          <div><strong>Service</strong><span>{String(health?.service ?? "Unknown")}</span></div>
          <div><strong>Database</strong><span>{String(health?.database ?? "Unknown")}</span></div>
          <div><strong>Remote Audit API</strong><span>{String(health?.remoteAuditApiUrl ?? "Local only")}</span></div>
          <div><strong>Remote Auth</strong><span>{String(health?.remoteAuthConfigured ?? false)}</span></div>
        </div>
      </article>
    </PageChrome>
  );
}

export function AdminPanelPage() {
  const [users, setUsers] = useState<Row[]>([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  async function load() {
    try {
      const payload = await apiFetch<{ users: Row[] }>("/users");
      setUsers(payload.users);
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load users");
    }
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNotice("");
    setError("");
    try {
      await apiFetch("/admin/users", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, email, password, role }),
      });
      setName("");
      setEmail("");
      setPassword("");
      setRole("user");
      setNotice("User created successfully.");
      await load();
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Could not create user");
    }
  }

  async function deleteUser(userId: string, email: string) {
    setNotice("");
    setError("");
    if (!window.confirm(`Delete user ${email}?`)) return;
    try {
      await apiFetch(`/admin/users/${userId}`, { method: "DELETE" });
      setNotice("User deleted successfully.");
      await load();
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "Could not delete user");
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  return (
    <PageChrome title="Admin Panel" description="Create accounts, assign roles, and revoke access.">
      {notice ? <div className="success-state">{notice}</div> : null}
      {error ? <div className="backend-error">{error}</div> : null}
      <section className="content-grid single-view">
        <article className="panel tool-panel">
          <div className="panel-heading"><div><h2>Create User</h2><p>Administrators manage access. Auditors read logs. Users submit prompts. Approvers review other users’ requests.</p></div></div>
          <form className="prompt-form" onSubmit={createUser}>
            <label>Name<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
            <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={12} maxLength={128} required /></label>
            <label>Role
              <select value={role} onChange={(event) => setRole(event.target.value as Role)}>
                <option value="admin">admin - all privileges</option>
                <option value="auditor">auditor - read only audit log</option>
                <option value="user">user - submit prompts</option>
                <option value="approver">approver - review requests</option>
              </select>
            </label>
            <button type="submit">Create User</button>
          </form>
        </article>
        <article className="panel audit-panel">
          <div className="panel-heading"><div><h2>Existing Users</h2><p>Local FastAPI accounts.</p></div></div>
          <div className="simple-table">
            <div><strong>Name</strong><strong>Email</strong><strong>Role</strong><strong>Prompts</strong><strong>Action</strong></div>
            {users.map((item) => (
              <div key={String(item.email)}>
                <span>{item.name}</span>
                <span>{item.email}</span>
                <span><select aria-label={`Role for ${item.email}`} value={String(item.role)} onChange={(event) => {
                  void apiFetch(`/admin/users/${item.id}`, {
                    method: "PATCH",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ role: event.target.value, active: Boolean(item.active) }),
                  }).then(load).catch((updateError: Error) => setError(updateError.message));
                }}>{["admin", "auditor", "user", "approver"].map((availableRole) => <option key={availableRole}>{availableRole}</option>)}</select></span>
                <span>{item.promptCount}</span>
                <span>
                  <button type="button" onClick={() => {
                    void apiFetch(`/admin/users/${item.id}`, {
                      method: "PATCH",
                      headers: { "content-type": "application/json" },
                      body: JSON.stringify({ role: item.role, active: !item.active }),
                    }).then(load).catch((updateError: Error) => setError(updateError.message));
                  }}>{item.active ? "Disable" : "Enable"}</button>
                  <button className="danger-button" type="button" onClick={() => void deleteUser(String(item.id), String(item.email))}>Delete</button>
                </span>
              </div>
            ))}
          </div>
        </article>
      </section>
    </PageChrome>
  );
}
