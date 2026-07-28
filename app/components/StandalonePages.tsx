"use client";

import { FormEvent, useEffect, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders, getStoredToken } from "../lib/api";

type Role = "admin" | "auditor" | "user";
type Row = Record<string, string | number | boolean | null>;

function logout() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.location.href = "/login";
}

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
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    logout();
    throw new Error("Login expired");
  }
  if (!response.ok) {
    throw new Error(String(payload.detail ?? "Backend request failed"));
  }
  return payload as T;
}

function PageChrome({
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
    const raw = window.localStorage.getItem(USER_KEY);
    if (raw) setUser(JSON.parse(raw) as Row);
  }, []);

  return (
    <main className="dashboard-shell page-only-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark">S</div>
          <div>
            <strong>Secure AI</strong>
            <span>Prompt Gateway</span>
          </div>
        </div>
        <nav aria-label="Page navigation">
          <button type="button" onClick={() => { window.location.href = "/"; }}><span className="nav-dot" />Dashboard</button>
          <button type="button" className={title === "Audit Logs" ? "active" : ""} onClick={() => { window.location.href = "/audit-logs"; }}><span className="nav-dot" />Audit Logs</button>
          <button type="button" className={title === "System Settings" ? "active" : ""} onClick={() => { window.location.href = "/system-settings"; }}><span className="nav-dot" />System Settings</button>
          {user?.role === "admin" ? <button type="button" className={title === "Admin Panel" ? "active" : ""} onClick={() => { window.location.href = "/admin"; }}><span className="nav-dot" />Admin Panel</button> : null}
        </nav>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div>
            <p>Secure AI Prompt Gateway</p>
            <h1>{title}</h1>
            <span>{description}</span>
          </div>
          <div className="topbar-actions">
            <div className="admin-chip">
              <span />
              <div>
                <strong>{String(user?.name ?? "sec.admin")}</strong>
                <small>{String(user?.role ?? "role")}</small>
              </div>
            </div>
            <button type="button" onClick={logout}>Logout</button>
          </div>
        </header>
        {children}
      </section>
    </main>
  );
}

export function AuditLogsPage() {
  const [events, setEvents] = useState<Row[]>([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      const payload = await apiFetch<Row[]>("/audit/events");
      setEvents(payload);
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load audit logs");
    }
  }

  useEffect(() => { void load(); }, []);

  return (
    <PageChrome title="Audit Logs" description="Separate audit log webpage. Admin and auditor roles can read this page.">
      {error ? <div className="backend-error">{error}</div> : null}
      <article className="panel audit-panel single-view">
        <div className="panel-heading">
          <div><h2>Audit Log Records</h2><p>Read-only masked event history from FastAPI SQLite.</p></div>
          <button type="button" onClick={() => void load()}>Reload</button>
        </div>
        <div className="audit-table">
          <div className="audit-header"><span>Event ID</span><span>Time</span><span>User</span><span>Action</span><span>Finding</span><span>Masked Output</span><span>Status</span></div>
          {events.map((event) => (
            <div className="audit-row" key={String(event.id)}>
              <span>{event.id}</span><span>{event.timestamp}</span><span>{event.actor}</span><span>{event.action}</span>
              <span><em className={`risk-badge ${String(event.risk).toLowerCase()}`}>{event.finding}</em></span>
              <span>{event.maskedOutput}</span><span>{event.status}</span>
            </div>
          ))}
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

  useEffect(() => { void load(); }, []);

  return (
    <PageChrome title="Admin Panel" description="Create users and assign admin, auditor, or user roles.">
      {notice ? <div className="success-state">{notice}</div> : null}
      {error ? <div className="backend-error">{error}</div> : null}
      <section className="content-grid single-view">
        <article className="panel tool-panel">
          <div className="panel-heading"><div><h2>Create User</h2><p>Admin has all privileges. Auditor reads audit logs. User is read-only dashboard.</p></div></div>
          <form className="prompt-form" onSubmit={createUser}>
            <label>Name<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
            <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={8} required /></label>
            <label>Role
              <select value={role} onChange={(event) => setRole(event.target.value as Role)}>
                <option value="admin">admin - all privileges</option>
                <option value="auditor">auditor - read only audit log</option>
                <option value="user">user - read only dashboard</option>
              </select>
            </label>
            <button type="submit">Create User</button>
          </form>
        </article>
        <article className="panel audit-panel">
          <div className="panel-heading"><div><h2>Existing Users</h2><p>Local FastAPI accounts.</p></div></div>
          <div className="simple-table">
            <div><strong>Name</strong><strong>Email</strong><strong>Role</strong><strong>Prompts</strong><strong>Blocked</strong></div>
            {users.map((item) => <div key={String(item.email)}><span>{item.name}</span><span>{item.email}</span><span>{item.role}</span><span>{item.promptCount}</span><span>{item.blockedCount}</span></div>)}
          </div>
        </article>
      </section>
    </PageChrome>
  );
}
