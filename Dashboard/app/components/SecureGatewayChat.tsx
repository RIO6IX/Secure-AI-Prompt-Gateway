"use client";

import { FormEvent, useEffect, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders, getStoredToken } from "../lib/api";

type User = {
  name: string;
  email: string;
  role: string;
};

type GatewayEntity = {
  entityType: string;
  category: string;
  maskedValue: string;
  riskLevel: string;
  confidence: number;
};

type GatewayResult = {
  requestId: string;
  userPrompt: string;
  sanitizedPrompt: string;
  assistantMessage: string;
  policyDecision: string;
  actionTaken: string;
  riskLevel: string;
  riskScore: number;
  containsSensitiveData: boolean;
  detectedEntities: GatewayEntity[];
  auditEvents: Array<Record<string, string | number | boolean | null>>;
  ollamaModel: string;
  ollamaAvailable: boolean;
  componentPlaceholders: Record<string, string>;
};

const examples = [
  {
    title: "API issue with key",
    time: "Now",
    preview: "Please fix this API issue...",
    prompt: "Please fix this API issue. My API key is sk_live_ABC123456789 and customer email is nimal@company.com",
  },
  {
    title: "Database connection help",
    time: "10:15 AM",
    preview: "How to optimize the query...",
    prompt: "Can you review this database URL? postgresql://admin:Password123@db.internal.local:5432/payments",
  },
  {
    title: "Security review request",
    time: "Yesterday",
    preview: "Please review this auth flow...",
    prompt: "Please review this auth flow. Bearer eyJhbGciOiJIUzI1NiJ9.dummyTokenHeaderPayload.signatureValue",
  },
  {
    title: "Code refactor guidance",
    time: "May 16",
    preview: "Refactor this function...",
    prompt: "def process_customer(record):\n    return record['email']",
  },
];

function logout() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.location.href = "/login";
}

function riskClass(risk: string) {
  return risk.toLowerCase();
}

function displayType(type: string) {
  return type.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function SecureGatewayChat() {
  const [user, setUser] = useState<User | null>(null);
  const [prompt, setPrompt] = useState(examples[0].prompt);
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      window.location.href = "/login";
      return;
    }
    const rawUser = window.localStorage.getItem(USER_KEY);
    if (rawUser) setUser(JSON.parse(rawUser) as User);
    setDarkMode(window.localStorage.getItem("secure_gateway_dark_mode") === "true");
  }, []);

  function toggleDarkMode() {
    setDarkMode((current) => {
      const next = !current;
      window.localStorage.setItem("secure_gateway_dark_mode", String(next));
      return next;
    });
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = getStoredToken();
      if (!token) throw new Error("Login required");
      const response = await fetch(`${API_BASE_URL}/gateway/chat`, {
        method: "POST",
        headers: {
          ...authHeaders(token),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          prompt,
          service: "Ollama Qwen2.5",
          department: "Engineering",
          forward_to_ollama: true,
        }),
      });
      const payload = (await response.json()) as GatewayResult & { detail?: string };
      if (response.status === 401) {
        logout();
        return;
      }
      if (!response.ok) throw new Error(String(payload.detail ?? "Gateway request failed"));
      setResult(payload);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Gateway request failed");
    } finally {
      setLoading(false);
    }
  }

  const currentRisk = result?.riskLevel ?? "LOW";
  const entities = result?.detectedEntities ?? [];
  const sanitized = result?.sanitizedPrompt ?? "Submit a prompt to see the sanitized version before it reaches Ollama.";

  return (
    <main className={`gateway-shell ${darkMode ? "gateway-dark" : ""}`}>
      <aside className="gateway-sidebar">
        <div className="gateway-brand">
          <div className="gateway-logo">S</div>
          <div>
            <strong>Secure AI</strong>
            <span>Prompt Gateway</span>
          </div>
        </div>
        <button className="new-chat" type="button" onClick={() => { setPrompt(""); setResult(null); }}>+ New Chat</button>
        <section className="chat-history" aria-label="Chat history">
          <h2>Chat History</h2>
          {examples.map((item, index) => (
            <button
              key={item.title}
              type="button"
              className={index === 0 ? "active" : ""}
              onClick={() => setPrompt(item.prompt)}
            >
              <span className="chat-bubble-icon" />
              <span>
                <strong>{item.title}</strong>
                <small>{item.preview}</small>
              </span>
              <em>{item.time}</em>
            </button>
          ))}
        </section>
        <div className="provider-card">
          <p>Connected Provider</p>
          <strong>{result?.ollamaModel ?? "qwen2.5:3b"}</strong>
          <span className={result?.ollamaAvailable === false ? "offline" : ""}>
            {result?.ollamaAvailable === false ? "Ollama offline" : "Local Ollama API"}
          </span>
          <hr />
          <p>User Role</p>
          <strong>{user?.role ?? "user"}</strong>
        </div>
        <a className="dashboard-link" href="/dashboard">Open Security Dashboard</a>
      </aside>

      <section className="gateway-chat">
        <header className="gateway-header">
          <div className="secure-badge">OK</div>
          <div>
            <h1>Intercept - Detect - Sanitize - Forward</h1>
            <p>Your prompts are inspected locally before reaching Ollama.</p>
          </div>
          <div className="system-status">
            <button className="theme-toggle" type="button" onClick={toggleDarkMode}>
              {darkMode ? "Light Mode" : "Dark Mode"}
            </button>
            <span>System Status</span>
            <strong>Secure</strong>
          </div>
        </header>

        <div className="today-divider"><span>Today</span></div>

        <div className="message-row user-message">
          <article>
            <header><strong>You</strong><span>{new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></header>
            <p>{result?.userPrompt ?? prompt}</p>
          </article>
          <div className="avatar">U</div>
        </div>

        <div className="message-row gateway-message">
          <div className="gateway-small-logo">S</div>
          <article>
            <header><strong>Secure AI Prompt Gateway</strong><span>{new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></header>
            <p>
              {result?.containsSensitiveData
                ? "Sensitive data detected in your prompt. Your input was converted into a sanitized version before forwarding."
                : "No sensitive data was detected. The prompt can be forwarded through the local gateway."}
            </p>
            <div className="action-card">
              <strong>Action Taken</strong>
              <span>{result?.actionTaken ?? "Waiting for prompt analysis."}</span>
            </div>
            <p>{result?.assistantMessage ?? "Submit a prompt to receive a local Ollama response or a safe offline status."}</p>
            <details open>
              <summary>What was sent to the AI provider</summary>
              <pre>{sanitized}</pre>
            </details>
          </article>
        </div>

        {error ? <div className="gateway-error">{error}</div> : null}

        <form className="gateway-composer" onSubmit={submit}>
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Type your message..."
            rows={3}
            required
          />
          <div className="composer-actions">
            <span>Local inspection</span>
            <span>Shield inspection enabled</span>
            <button type="submit" disabled={loading}>{loading ? "Scanning..." : "Send"}</button>
          </div>
        </form>
      </section>

      <aside className="risk-panel">
        <section className="risk-card">
          <h2>Detection & Risk Analysis</h2>
          <div className="panel-block">
            <h3>Detected Sensitive Data</h3>
            {entities.length ? entities.map((entity) => (
              <div className="entity-row" key={`${entity.entityType}-${entity.maskedValue}`}>
                <span>{entity.category === "CREDENTIAL" ? "Key" : entity.category}</span>
                <strong>{displayType(entity.entityType)}</strong>
                <code>{entity.maskedValue}</code>
              </div>
            )) : <p className="empty-hint">No sensitive data detected yet.</p>}
          </div>

          <div className="panel-block risk-level-block">
            <h3>Risk Level</h3>
            <strong className={`risk-pill ${riskClass(currentRisk)}`}>{currentRisk}</strong>
            <p>{result?.containsSensitiveData ? "Sensitive data detected. Review the sanitized preview." : "Prompt is currently low risk."}</p>
          </div>

          <div className="panel-block">
            <h3>Sanitized Prompt Preview</h3>
            <pre>{sanitized}</pre>
          </div>

          <div className="panel-block">
            <h3>Policy Decision</h3>
            <div className="decision-grid">
              <span>Block & Deny</span>
              <span>Warn & Proceed</span>
              <strong>{result?.policyDecision ?? "Pending"}</strong>
            </div>
          </div>
        </section>
      </aside>
    </main>
  );
}
