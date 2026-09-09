"use client";

import { FormEvent, KeyboardEvent, useEffect, useRef, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY, authHeaders } from "../lib/api";

type StoredUser = { name: string; email: string; role: string };
type InspectionResult = {
  id: string;
  status: string;
  risk: string;
  finding: string;
  policyRule: string;
  maskedOutput: string;
};
type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  metadata?: string;
  decision?: string;
};

function readStoredUser(): StoredUser | null {
  try {
    const stored = window.localStorage.getItem(USER_KEY);
    return stored ? (JSON.parse(stored) as StoredUser) : null;
  } catch {
    return null;
  }
}

export function SecureChatWorkspace() {
  const [user, setUser] = useState<StoredUser | null>(null);
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const [ready, setReady] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const token = window.localStorage.getItem(TOKEN_KEY);
    const storedUser = readStoredUser();
    if (!token || !storedUser) {
      window.location.href = "/login";
      return;
    }
    const timer = window.setTimeout(() => {
      setUser(storedUser);
      setReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!textareaRef.current) return;
    textareaRef.current.style.height = "auto";
    textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 170)}px`;
  }, [prompt]);

  function clearChat() {
    setMessages([]);
    setPrompt("");
    setError("");
    requestAnimationFrame(() => textareaRef.current?.focus());
  }

  function logout() {
    window.localStorage.removeItem(TOKEN_KEY);
    window.localStorage.removeItem(USER_KEY);
    window.location.href = "/login";
  }

  async function submitPrompt(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = prompt.trim();
    if (!value || !user) {
      setError("Enter a message before sending.");
      return;
    }

    setError("");
    setSending(true);
    setPrompt("");
    setMessages((current) => [...current, { id: crypto.randomUUID(), role: "user", content: value }]);

    try {
      const response = await fetch(`${API_BASE_URL}/inspect`, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          actor: user.email,
          department: "Unknown",
          service: "ChatGPT Enterprise",
          prompt: value,
          source: "secure-chat-ui",
        }),
      });
      const result = (await response.json()) as InspectionResult & { detail?: string };
      if (!response.ok) throw new Error(result.detail ?? "The prompt could not be inspected.");

      const content = result.status === "Blocked"
        ? "This message was blocked because it contains protected information. Remove the sensitive content and try again."
        : result.status === "Sanitized"
          ? result.maskedOutput
          : "No sensitive information was detected. This prompt is approved for external AI use.";

      setMessages((current) => [...current, {
        id: crypto.randomUUID(),
        role: "assistant",
        content,
        decision: result.status,
        metadata: `${result.risk} risk · ${result.finding} · ${result.policyRule}`,
      }]);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "The local connection was interrupted. Please try again.");
    } finally {
      setSending(false);
      requestAnimationFrame(() => textareaRef.current?.focus());
    }
  }

  function handleComposerKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.ctrlKey && event.key === "Enter") {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  }

  if (!ready || !user) return <main className="secure-loading">Opening your secure workspace…</main>;

  const displayName = user.name || user.email;
  const isAdmin = user.role.toLowerCase() === "admin";

  return (
    <main className="secure-chat-shell" aria-label="Secure AI workspace">
      <aside className="secure-sidebar">
        <div className="secure-brand">
          <span className="secure-shield small" aria-hidden="true">S</span>
          <div><strong>Secure AI</strong><small>Prompt Gateway</small></div>
        </div>
        <button className="secure-new-chat" type="button" onClick={clearChat}><span aria-hidden="true">+</span> New secure chat</button>
        <div className="secure-sidebar-message">
          <span className="secure-live-dot" aria-hidden="true" />
          <div><strong>Protection active</strong><small>Every message is inspected locally</small></div>
        </div>
        <div className="secure-no-history"><strong>No saved history</strong><p>Conversations remain temporary in this browser session.</p></div>
        <div className="secure-sidebar-bottom">
          {isAdmin ? <a className="secure-sidebar-action" href="/audit-logs">Audit dashboard</a> : null}
          <button className="secure-sidebar-action" type="button" onClick={clearChat}>Clear current chat</button>
          <div className="secure-identity-row">
            <span className="secure-avatar" aria-hidden="true">{displayName.charAt(0).toUpperCase()}</span>
            <div><strong>{displayName}</strong><small>{user.role.toUpperCase()}</small></div>
            <button className="secure-icon-button" type="button" onClick={logout} aria-label="Sign out" title="Sign out">→</button>
          </div>
        </div>
      </aside>

      <section className="secure-chat-main">
        <header className="secure-chat-header">
          <div><strong>Protected AI Assistant</strong><small>{messages.length ? "Temporary context active" : "Temporary conversation"}</small></div>
          <span className="secure-privacy-pill">Not saved</span>
        </header>
        <div className="secure-chat-feed" aria-live="polite">
          {messages.length === 0 ? (
            <div className="secure-welcome-state">
              <div className="secure-welcome-icon" aria-hidden="true">S</div>
              <h1>How can I help securely?</h1>
              <p>Your message is checked for sensitive information before it can be approved for an external AI service.</p>
              <div className="secure-safety-grid">
                <div><strong>Private by default</strong><span>Messages are processed by the local gateway.</span></div>
                <div><strong>Sensitive data protection</strong><span>PII, payment data, and credentials are detected.</span></div>
                <div><strong>Clear decisions</strong><span>See whether a message is allowed, sanitized, or blocked.</span></div>
              </div>
            </div>
          ) : messages.map((message) => (
            <article className={`secure-message-row ${message.role}`} key={message.id}>
              <span className="secure-message-avatar" aria-hidden="true">{message.role === "assistant" ? "S" : displayName.charAt(0).toUpperCase()}</span>
              <div className="secure-message-content">
                <header><strong>{message.role === "assistant" ? "Secure AI Assistant" : "You"}</strong><span>{message.role === "assistant" ? "Security inspection" : "Submitted for inspection"}</span></header>
                <p>{message.content}</p>
                {message.decision ? <div className={`secure-decision ${message.decision.toLowerCase()}`}><strong>{message.decision}</strong><span>{message.metadata}</span></div> : null}
              </div>
            </article>
          ))}
        </div>
        <div className="secure-composer-wrap">
          {error ? <p className="secure-error" role="alert">{error}</p> : null}
          <form className="secure-composer" onSubmit={submitPrompt}>
            <label className="sr-only" htmlFor="secure-prompt-input">Message the protected AI assistant</label>
            <textarea ref={textareaRef} id="secure-prompt-input" maxLength={10000} rows={1} required value={prompt} onChange={(event) => setPrompt(event.target.value)} onKeyDown={handleComposerKeyDown} placeholder="Message the protected AI assistant..." />
            <button className="secure-send-button" type="submit" disabled={sending} aria-label="Send securely">{sending ? "…" : "↑"}</button>
            <div className="secure-composer-meta"><span>{prompt.length.toLocaleString()} / 10,000</span><span>Ctrl + Enter to send</span></div>
          </form>
          <p className="secure-composer-caption">Secure AI Prompt Gateway checks every new message. Conversation context is temporary and not written to history.</p>
        </div>
      </section>
    </main>
  );
}
