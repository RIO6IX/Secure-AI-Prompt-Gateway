"use client";

import { FormEvent, KeyboardEvent, useEffect, useRef, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, apiErrorMessage, authHeaders, getStoredToken } from "../lib/api";
import { setStoredItem, useStoredItem, useStoredUser } from "../lib/storage";

type GatewayEntity = {
  entityType: string;
  category: string;
  maskedValue: string;
  riskLevel: string;
  confidence: number;
  start: number;
  end: number;
};

type RiskFactor = {
  entity_type: string;
  points: number;
  reason: string;
};

type Replacement = {
  placeholder: string;
  entity_type: string;
  masked_value: string;
};

type ModelStatus = "answered" | "blocked" | "not_forwarded" | "unavailable";

type GatewayResult = {
  requestId: string;
  conversationId: string;
  userPrompt: string;
  sanitizedPrompt: string;
  assistantMessage: string;
  policyDecision: string;
  actionTaken: string;
  riskLevel: string;
  riskScore: number;
  riskAssessment: { score: number; level: string; summary: string; factors: RiskFactor[] };
  replacements: Replacement[];
  replyMaskedCount: number;
  replyFindingTypes: string[];
  containsSensitiveData: boolean;
  detectedEntities: GatewayEntity[];
  auditEvents: Array<Record<string, string | number | boolean | null>>;
  ollamaModel: string;
  ollamaAvailable: boolean;
  modelStatus: ModelStatus;
  modelError: string | null;
  blockReason: string | null;
  componentPlaceholders: Record<string, string>;
};

type Turn = {
  id: string;
  prompt: string;
  sentAt: Date;
  result?: GatewayResult;
  error?: string;
  notice?: string;
};

type BackendHealth = {
  reachable: boolean;
  nerLoaded: boolean;
};

// Synthetic prompts for trying the gateway. They are labelled as examples in
// the UI; none of these values belong to a real person or system.
const examples = [
  {
    title: "API key + customer email",
    prompt: "Please fix this API issue. My API key is sk_live_51HxQpT2eZvKYlo2C8a1b2c3 and customer email is nimal@company.lk",
  },
  {
    title: "Database connection string",
    prompt: "Can you review this database URL? postgresql://admin:Password123@db.internal.local:5432/payments",
  },
  {
    title: "Card number and NIC",
    prompt: "Refund customer NIC 199512345678, card 4539 1488 0343 6467, phone +94 77 123 4567",
  },
  {
    title: "Code with a password",
    prompt: "def connect():\n    password = 'Sup3rS3cret!'\n    return db.connect(host='10.0.0.5')",
  },
];

const DARK_MODE_KEY = "secure_gateway_dark_mode";

function logout() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.location.assign("/login");
}

function riskClass(risk: string) {
  return risk.toLowerCase();
}

function displayType(type: string) {
  return type.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function timeLabel(date: Date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function detectedTypes(result: GatewayResult) {
  return [...new Set(result.detectedEntities.map((entity) => displayType(entity.entityType)))];
}

function summarize(prompt: string) {
  const firstLine = prompt.trim().split("\n")[0];
  return firstLine.length > 42 ? `${firstLine.slice(0, 42)}...` : firstLine;
}

async function readJson(response: Response): Promise<(GatewayResult & { detail?: unknown }) | null> {
  const contentType = response.headers.get("content-type") ?? "";
  return contentType.includes("application/json") ? response.json() : null;
}

export function SecureGatewayChat() {
  const user = useStoredUser();
  const darkMode = useStoredItem(DARK_MODE_KEY) === "true";
  const [prompt, setPrompt] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<BackendHealth | null>(null);
  // Server-side conversation: keeps sanitized history and consistent placeholders.
  const [conversationId, setConversationId] = useState<string | null>(null);
  const threadEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      window.location.assign("/login");
      return;
    }
    fetch(`${API_BASE_URL}/health`)
      .then((response) => response.json())
      .then((body: { detectionEngine?: { ner_model_available?: boolean } }) =>
        setHealth({ reachable: true, nerLoaded: Boolean(body.detectionEngine?.ner_model_available) }),
      )
      .catch(() => setHealth({ reachable: false, nerLoaded: false }));
  }, []);

  useEffect(() => {
    threadEnd.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns]);

  function toggleDarkMode() {
    setStoredItem(DARK_MODE_KEY, String(!darkMode));
  }

  function newChat() {
    const token = getStoredToken();
    if (conversationId && token) {
      // Tell the gateway to forget the history and placeholder map now rather than at expiry.
      void fetch(`${API_BASE_URL}/gateway/conversations/${encodeURIComponent(conversationId)}`, {
        method: "DELETE",
        headers: authHeaders(token),
      }).catch(() => undefined);
    }
    setConversationId(null);
    setTurns([]);
    setSelectedId(null);
    setPrompt("");
  }

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed || loading) return;

    const token = getStoredToken();
    if (!token) {
      logout();
      return;
    }

    const turn: Turn = { id: crypto.randomUUID(), prompt: text, sentAt: new Date() };
    setTurns((current) => [...current, turn]);
    setSelectedId(turn.id);
    setPrompt("");
    setLoading(true);

    let update: Partial<Turn>;
    try {
      const post = (conversation: string | null) =>
        fetch(`${API_BASE_URL}/gateway/chat`, {
          method: "POST",
          headers: {
            ...authHeaders(token),
            "content-type": "application/json",
          },
          body: JSON.stringify({
            prompt: text,
            service: "Ollama Qwen2.5",
            department: "Engineering",
            forward_to_ollama: true,
            conversation_id: conversation ?? undefined,
          }),
        });
      let response = await post(conversationId);
      let restarted = false;
      if (response.status === 404 && conversationId) {
        // The conversation expired on the server; continue in a fresh one.
        response = await post(null);
        restarted = true;
      }
      if (response.status === 401) {
        logout();
        return;
      }
      const payload = await readJson(response);
      if (!response.ok || !payload) throw new Error(apiErrorMessage(payload?.detail, "Gateway request failed"));
      setConversationId(payload.conversationId);
      update = {
        result: payload,
        notice: restarted ? "The previous conversation had expired, so this message started a new one." : undefined,
      };
    } catch (requestError) {
      const message =
        requestError instanceof TypeError
          ? `Cannot reach the gateway backend at ${API_BASE_URL}. Is it running?`
          : requestError instanceof Error
            ? requestError.message
            : "Gateway request failed";
      update = { error: message };
    } finally {
      setLoading(false);
    }
    setTurns((current) => current.map((item) => (item.id === turn.id ? { ...item, ...update } : item)));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void send(prompt);
  }

  function onComposerKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void send(prompt);
    }
  }

  const selected = turns.find((turn) => turn.id === selectedId) ?? turns.at(-1);
  const result = selected?.result;
  const currentRisk = result?.riskLevel ?? "LOW";
  const entities = result?.detectedEntities ?? [];
  const lastModel = [...turns]
    .reverse()
    .find((turn) => turn.result?.modelStatus === "answered" || turn.result?.modelStatus === "unavailable")?.result;
  const statusLabel = health === null ? "Checking..." : health.reachable ? "Online" : "Backend offline";

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
        <button className="new-chat" type="button" onClick={newChat}>+ New Chat</button>
        <section className="chat-history" aria-label="Prompts in this session">
          <h2>This Session</h2>
          {turns.length ? turns.map((turn) => (
            <button
              key={turn.id}
              type="button"
              className={turn.id === selected?.id ? "active" : ""}
              onClick={() => setSelectedId(turn.id)}
            >
              <span className="chat-bubble-icon" />
              <span>
                <strong>{summarize(turn.result?.sanitizedPrompt ?? turn.prompt)}</strong>
                <small>
                  {turn.error
                    ? "Failed"
                    : turn.result
                      ? turn.result.modelStatus === "blocked"
                        ? "Blocked"
                        : `${turn.result.riskLevel} risk`
                      : "Waiting..."}
                </small>
              </span>
              <em>{timeLabel(turn.sentAt)}</em>
            </button>
          )) : <p className="empty-hint">Prompts you send appear here. Nothing is stored after you close the tab.</p>}
        </section>
        <section className="chat-history" aria-label="Example prompts">
          <h2>Example Prompts</h2>
          {examples.map((item) => (
            <button key={item.title} type="button" onClick={() => setPrompt(item.prompt)}>
              <span className="chat-bubble-icon" />
              <span>
                <strong>{item.title}</strong>
                <small>Synthetic test data</small>
              </span>
            </button>
          ))}
        </section>
        <div className="provider-card">
          <p>Connected Provider</p>
          <strong>{lastModel?.ollamaModel ?? "qwen2.5:3b"}</strong>
          <span className={lastModel?.ollamaAvailable === false ? "offline" : ""}>
            {lastModel ? (lastModel.ollamaAvailable ? "Local Ollama API" : "Ollama offline") : "Local Ollama API"}
          </span>
          <hr />
          <p>Signed in as</p>
          <strong>{user?.email ?? "-"}</strong>
          <span>{user?.role ?? "user"}</span>
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
            <span>Gateway Backend</span>
            <strong className={health && !health.reachable ? "offline" : ""}>{statusLabel}</strong>
            {health?.reachable ? <small>{health.nerLoaded ? "NER model loaded" : "Regex-only mode"}</small> : null}
          </div>
        </header>

        <div className="chat-thread">
          {turns.length === 0 ? (
            <div className="chat-empty">
              <strong>Send a prompt to see what the gateway does with it.</strong>
              <p>Secrets, card numbers and personal data are detected and masked before anything is sent to the model.</p>
            </div>
          ) : null}

          {turns.map((turn) => (
            <div key={turn.id} className="chat-turn">
              <div className="message-row user-message">
                <article>
                  <header><strong>You</strong><span>{timeLabel(turn.sentAt)}</span></header>
                  <p>{turn.prompt}</p>
                </article>
                <div className="avatar">{user?.name?.[0]?.toUpperCase() ?? "U"}</div>
              </div>

              <div className="message-row gateway-message">
                <div className="gateway-small-logo">S</div>
                <article>
                  <header><strong>Secure AI Prompt Gateway</strong></header>
                  {turn.error ? (
                    <div className="gateway-error">{turn.error}</div>
                  ) : !turn.result ? (
                    <p className="gateway-pending" role="status">
                      Checking the prompt, then waiting for {lastModel?.ollamaModel ?? "the local model"}. A reply can
                      take up to a minute on a CPU.
                    </p>
                  ) : (
                    <TurnResult result={turn.result} notice={turn.notice} onShowAnalysis={() => setSelectedId(turn.id)} />
                  )}
                </article>
              </div>
            </div>
          ))}
          <div ref={threadEnd} />
        </div>

        <form className="gateway-composer" onSubmit={submit}>
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            onKeyDown={onComposerKeyDown}
            placeholder="Type your message... (Enter to send, Shift+Enter for a new line)"
            rows={3}
            required
          />
          <div className="composer-actions">
            <span>Inspected locally before forwarding</span>
            <button type="submit" disabled={loading || !prompt.trim()}>{loading ? "Waiting..." : "Send"}</button>
          </div>
        </form>
      </section>

      <aside className="risk-panel">
        <section className="risk-card">
          <h2>Detection & Risk Analysis</h2>
          <div className="panel-block">
            <h3>Detected Sensitive Data</h3>
            {entities.length ? entities.map((entity) => (
              <div className="entity-row" key={`${entity.entityType}-${entity.start}-${entity.end}`}>
                <span>{entity.category === "CREDENTIAL" ? "Key" : entity.category}</span>
                <strong>{displayType(entity.entityType)}</strong>
                <code title={`Confidence ${Math.round(entity.confidence * 100)}%`}>{entity.maskedValue}</code>
              </div>
            )) : <p className="empty-hint">{result ? "Nothing sensitive in this prompt." : "No prompt analyzed yet."}</p>}
          </div>

          <div className="panel-block risk-level-block">
            <h3>Risk Level</h3>
            <strong className={`risk-pill ${riskClass(currentRisk)}`}>{currentRisk}</strong>
            <p>{result ? result.riskAssessment.summary : "Send a prompt to calculate its risk."}</p>
            {result?.riskAssessment.factors.length ? (
              <ul className="risk-factors">
                {result.riskAssessment.factors.map((factor) => (
                  <li key={factor.entity_type}>
                    <span>{factor.reason}</span>
                    <strong>+{factor.points}</strong>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>

          {result?.replacements.length ? (
            <div className="panel-block">
              <h3>Placeholders Used</h3>
              {result.replacements.map((item) => (
                <div className="entity-row" key={`${item.placeholder}-${item.masked_value}`}>
                  <strong>{item.placeholder}</strong>
                  <code>{item.masked_value}</code>
                </div>
              ))}
            </div>
          ) : null}

          <div className="panel-block">
            <h3>Sanitized Prompt Preview</h3>
            <pre>{result?.sanitizedPrompt ?? "The sanitized prompt appears here after analysis."}</pre>
          </div>

          <div className="panel-block">
            <h3>Policy Decision</h3>
            <div className="decision-grid">
              <strong>{result?.policyDecision ?? "Pending"}</strong>
              {result ? <span>Request {result.requestId.slice(0, 8)}</span> : null}
            </div>
          </div>
        </section>
      </aside>
    </main>
  );
}

function TurnResult({
  result,
  notice,
  onShowAnalysis,
}: {
  result: GatewayResult;
  notice?: string;
  onShowAnalysis: () => void;
}) {
  const types = detectedTypes(result);
  const forwarded = result.modelStatus === "answered" || result.modelStatus === "unavailable";

  if (result.modelStatus === "blocked") {
    return (
      <>
        <div className="blocked-card">
          <strong>Blocked by policy. Nothing was sent to the AI.</strong>
          <span>{result.blockReason ?? result.assistantMessage}</span>
        </div>
        {types.length ? (
          <div className="reply-section">
            <h4>Detected</h4>
            <div className="type-chips">{types.map((type) => <span key={type}>{type}</span>)}</div>
          </div>
        ) : null}
        <button className="link-button" type="button" onClick={onShowAnalysis}>Show analysis</button>
      </>
    );
  }

  return (
    <>
      <div className="action-card">
        <strong>Action Taken</strong>
        <span>{result.actionTaken}</span>
      </div>
      {notice ? <p className="reply-masked-note">{notice}</p> : null}
      {types.length ? (
        <div className="reply-section">
          <h4>Detected and masked</h4>
          <div className="type-chips">{types.map((type) => <span key={type}>{type}</span>)}</div>
        </div>
      ) : null}
      {forwarded ? (
        <div className="reply-section">
          <h4>{result.containsSensitiveData ? "Masked prompt sent to AI" : "Prompt sent to AI (unchanged)"}</h4>
          <pre>{result.sanitizedPrompt}</pre>
        </div>
      ) : null}
      <div className="reply-section">
        <h4>AI response{result.modelStatus === "answered" ? ` (${result.ollamaModel})` : ""}</h4>
        {result.modelStatus === "answered" ? (
          <p className="assistant-reply">{result.assistantMessage}</p>
        ) : result.modelStatus === "unavailable" ? (
          <div className="gateway-error">{result.modelError ?? result.assistantMessage}</div>
        ) : (
          <p className="empty-hint">Not sent to the AI. {result.assistantMessage}</p>
        )}
      </div>
      {result.replyMaskedCount ? (
        <p className="reply-masked-note">
          {result.replyMaskedCount} sensitive value(s) in this reply are shown masked
          {result.replyFindingTypes.length
            ? ` (including ${result.replyFindingTypes.map(displayType).join(", ")} generated by the model)`
            : ""}
          .
        </p>
      ) : null}
      <button className="link-button" type="button" onClick={onShowAnalysis}>Show analysis</button>
    </>
  );
}
