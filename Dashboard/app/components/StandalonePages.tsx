"use client";

import { FormEvent, useEffect, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders, getStoredToken } from "../lib/api";
import { useStoredUser } from "../lib/storage";

type Role = "admin" | "auditor" | "user";
type Row = Record<string, string | number | boolean | null>;

function RoleNotice({ message }: { message: string }) {
  return (
    <div className="backend-error">
      {message} <button type="button" onClick={() => { window.location.assign("/"); }}>Back to Gateway Chat</button>
    </div>
  );
}

function logout() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.location.assign("/login");
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getStoredToken();
  if (!token) {
    window.location.assign("/login");
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
  const user = useStoredUser();

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
          <button type="button" onClick={() => { window.location.assign("/"); }}><span className="nav-dot" />Gateway Chat</button>
          <button type="button" onClick={() => { window.location.assign("/dashboard"); }}><span className="nav-dot" />Dashboard</button>
          {user?.role === "admin" || user?.role === "auditor" ? <button type="button" className={title === "Audit Logs" ? "active" : ""} onClick={() => { window.location.assign("/audit-logs"); }}><span className="nav-dot" />Audit Logs</button> : null}
          <button type="button" className={title === "System Settings" ? "active" : ""} onClick={() => { window.location.assign("/system-settings"); }}><span className="nav-dot" />System Settings</button>
          {user?.role === "admin" ? <button type="button" className={title === "Admin Panel" ? "active" : ""} onClick={() => { window.location.assign("/admin"); }}><span className="nav-dot" />Admin Panel</button> : null}
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
  const [risk, setRisk] = useState("");
  const [status, setStatus] = useState("");
  const [service, setService] = useState("");
  const [actor, setActor] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  function auditQuery() {
    const params = new URLSearchParams();
    if (risk) params.set("risk", risk);
    if (status) params.set("status", status);
    if (service.trim()) params.set("service", service.trim());
    if (actor.trim()) params.set("actor", actor.trim());
    return params.toString();
  }

  async function load() {
    try {
      const query = auditQuery();
      const payload = await apiFetch<Row[]>(`/audit/events${query ? `?${query}` : ""}`);
      setEvents(payload);
      setNotice("");
      setError("");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load audit logs");
    }
  }

  async function exportCsv() {
    try {
      const token = getStoredToken();
      const query = auditQuery();
      const response = await fetch(`${API_BASE_URL}/reports/export${query ? `?${query}` : ""}`, { headers: authHeaders(token) });
      if (!response.ok) throw new Error("Could not export audit report");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "secure-ai-filtered-audit-report.csv";
      link.click();
      window.URL.revokeObjectURL(url);
      setNotice("Filtered CSV report downloaded.");
      setError("");
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : "Could not export audit report");
    }
  }

  const role = useStoredUser()?.role ?? "";
  const canViewAudit = role === "admin" || role === "auditor";

  useEffect(() => {
    if (!canViewAudit) return;
    apiFetch<Row[]>("/audit/events").then(setEvents, (loadError: unknown) =>
      setError(loadError instanceof Error ? loadError.message : "Could not load audit logs"),
    );
  }, [canViewAudit]);

  if (role && !canViewAudit) {
    return (
      <PageChrome title="Audit Logs" description="Separate audit log webpage. Admin and auditor roles can read this page.">
        <RoleNotice message="Audit logs are available to admin and auditor accounts only. Your own activity is on the Dashboard." />
      </PageChrome>
    );
  }

  return (
    <PageChrome title="Audit Logs" description="Separate audit log webpage. Admin and auditor roles can read this page.">
      {notice ? <div className="success-state">{notice}</div> : null}
      {error ? <div className="backend-error">{error}</div> : null}
      <article className="panel audit-panel single-view">
        <div className="panel-heading">
          <div><h2>Audit Log Records</h2><p>Read-only masked event history from FastAPI SQLite.</p></div>
          <div className="panel-actions">
            <button type="button" onClick={() => void load()}>Apply Filters</button>
            <button type="button" onClick={() => void exportCsv()}>Export CSV</button>
          </div>
        </div>
        <div className="filter-grid">
          <label>Risk
            <select value={risk} onChange={(event) => setRisk(event.target.value)}>
              <option value="">All risks</option>
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
          </label>
          <label>Status
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">All statuses</option>
              <option value="Allowed">Allowed</option>
              <option value="Detected">Detected</option>
              <option value="Sanitized">Sanitized</option>
              <option value="Blocked">Blocked</option>
              <option value="Forwarded">Forwarded</option>
              <option value="Queued">Queued</option>
            </select>
          </label>
          <label>Service<input value={service} onChange={(event) => setService(event.target.value)} placeholder="ChatGPT, Ollama, Gemini" /></label>
          <label>User<input value={actor} onChange={(event) => setActor(event.target.value)} placeholder="email or username" /></label>
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
          {!events.length ? <div className="audit-row"><span>No records</span><span /><span /><span /><span /><span>No matching audit events in SQLite.</span><span /></div> : null}
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
          <div><strong>Remote Audit API</strong><span>{health?.remoteAuditConfigured ? "Configured" : "Local only"}</span></div>
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

  const viewerRole = useStoredUser()?.role ?? "";
  const isAdmin = viewerRole === "admin";

  useEffect(() => {
    if (!isAdmin) return;
    apiFetch<{ users: Row[] }>("/users").then(
      (payload) => setUsers(payload.users),
      (loadError: unknown) => setError(loadError instanceof Error ? loadError.message : "Could not load users"),
    );
  }, [isAdmin]);

  if (viewerRole && !isAdmin) {
    return (
      <PageChrome title="Admin Panel" description="Create users and assign admin, auditor, or user roles.">
        <RoleNotice message="User management is available to admin accounts only." />
      </PageChrome>
    );
  }

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
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={12} autoComplete="new-password" required /></label>
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
            <div><strong>Name</strong><strong>Email</strong><strong>Role</strong><strong>Prompts</strong><strong>Action</strong></div>
            {users.map((item) => (
              <div key={String(item.email)}>
                <span>{item.name}</span>
                <span>{item.email}</span>
                <span>{item.role}</span>
                <span>{item.promptCount}</span>
                <span><button className="danger-button" type="button" onClick={() => void deleteUser(String(item.id), String(item.email))}>Delete</button></span>
              </div>
            ))}
          </div>
        </article>
      </section>
    </PageChrome>
  );
}
