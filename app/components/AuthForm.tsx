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
    <main className="auth-shell">
      <section className="auth-panel">
        <div className="brand-lockup">
          <div className="brand-mark">S</div>
          <div>
            <strong>Secure AI</strong>
            <span>Prompt Gateway</span>
          </div>
        </div>

        <div className="auth-copy">
          <p>{isRegister ? "Create local admin account" : "Security admin login"}</p>
          <h1>{isRegister ? "Register" : "Login"}</h1>
          <span>Use your local Python backend at {API_BASE_URL}</span>
        </div>

        <form onSubmit={submit}>
          {isRegister ? (
            <label>
              Full Name
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Security Admin" required />
            </label>
          ) : null}
          <label>
            Email
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="sec.admin@company.com" required />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Minimum 8 characters" minLength={8} required />
          </label>
          {error ? <div className="backend-error">{error}</div> : null}
          <button type="submit" disabled={loading}>
            {loading ? "Please wait..." : isRegister ? "Create Account" : "Login"}
          </button>
        </form>

        <a className="auth-switch" href={isRegister ? "/login" : "/register"}>
          {isRegister ? "Already registered? Login" : "Need an account? Register"}
        </a>
      </section>
    </main>
  );
}
