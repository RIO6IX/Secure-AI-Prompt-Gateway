"use client";

import { FormEvent, useState } from "react";
import { API_BASE_URL, TOKEN_KEY, USER_KEY } from "../lib/api";

type AuthMode = "login" | "register";

type AuthPayload = {
  token: string;
  user: {
    name: string;
    email: string;
    role: string;
  };
};

export function AuthForm({ mode }: { mode: AuthMode }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const isRegister = mode === "register";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/${mode}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(isRegister ? { name, email, password } : { email, password }),
      });
      const payload = (await response.json()) as AuthPayload & { detail?: string };
      if (!response.ok) throw new Error(payload.detail ?? "Authentication failed");

      window.localStorage.setItem(TOKEN_KEY, payload.token);
      window.localStorage.setItem(USER_KEY, JSON.stringify(payload.user));
      window.location.href = "/";
    } catch (authError) {
      setError(authError instanceof Error ? authError.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell secure-auth-shell">
      <div className="secure-auth-brand">
        <span className="secure-shield" aria-hidden="true">S</span>
        <div>
          <strong>Secure AI Prompt Gateway</strong>
          <small>Local protection before external AI</small>
        </div>
      </div>

      <section className="auth-panel secure-auth-panel">
        <div className="secure-brand">
          <span className="secure-shield small" aria-hidden="true">S</span>
          <div>
            <strong>Secure AI</strong>
            <small>Prompt Gateway</small>
          </div>
        </div>

        <div className="auth-copy">
          <p>{isRegister ? "Protected registration" : "Protected access"}</p>
          <h1>{isRegister ? "Create your secure workspace account" : "Sign in to your secure workspace"}</h1>
          <span>{isRegister ? "Registration creates a standard user account. Administrators assign elevated roles separately." : "Prompts are inspected locally before approved content can reach external AI."}</span>
        </div>

        <form onSubmit={submit}>
          {isRegister ? (
            <label>
              Full Name
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Your full name" autoComplete="name" required />
            </label>
          ) : null}
          <label>
            Email
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="name@company.com" autoComplete="email" required />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder={isRegister ? "Minimum 12 characters" : "Password"} minLength={isRegister ? 12 : 1} maxLength={128} autoComplete={isRegister ? "new-password" : "current-password"} required />
          </label>
          {error ? <div className="backend-error">{error}</div> : null}
          <button type="submit" disabled={loading}>
            {loading ? "Please wait..." : isRegister ? "Create secure account" : "Sign in securely"}
          </button>
        </form>

        <a className="auth-switch" href={isRegister ? "/login" : "/register"}>
          {isRegister ? "Already registered? Sign in" : "Need an account? Register"}
        </a>
        <p className="secure-privacy-note">Passwords are verified locally and never stored as plain text.</p>
      </section>
    </main>
  );
}
