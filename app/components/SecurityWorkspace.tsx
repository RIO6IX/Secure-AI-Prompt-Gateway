"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch, PageChrome } from "./StandalonePages";

type Rule = { id: string; name: string; category: string; action: string; enabled: boolean; roles: string[]; services: string[]; min_score: number; max_score: number };
type Policy = { version: number; rules: Rule[] };
type Approval = { id: string; requester: string; status: string; sanitized_prompt: string; service: string; policy_version: number; reason: string | null };
type Inspection = { decision: string; send_allowed: boolean; policyRule: string; maskedOutput: string; policy_version: number; approval_id?: string };

export function SecurityWorkspace() {
  const [user, setUser] = useState<{ id: string; role: string } | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [prompt, setPrompt] = useState("");
  const [service, setService] = useState("ChatGPT Enterprise");
  const [result, setResult] = useState<Inspection | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  async function reload() {
    const [identity, rules, queue] = await Promise.all([
      apiFetch<{ id: string; role: string }>("/auth/me"),
      apiFetch<Policy>("/security/policy"),
      apiFetch<Approval[]>("/security/approvals"),
    ]);
    setUser(identity); setPolicy(rules); setApprovals(queue);
  }

  useEffect(() => {
    let active = true;
    void Promise.all([
      apiFetch<{ id: string; role: string }>("/auth/me"),
      apiFetch<Policy>("/security/policy"),
      apiFetch<Approval[]>("/security/approvals"),
    ]).then(([identity, rules, queue]) => {
      if (active) { setUser(identity); setPolicy(rules); setApprovals(queue); }
    }).catch((e: Error) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, []);

  async function run(action: () => Promise<void>) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : "Request failed"); }
    finally { setBusy(false); }
  }

  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(async () => {
      const response = await apiFetch<Inspection>("/inspect", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ prompt, service, actor: "session" }) });
      setResult(response); setPrompt("");
      setApprovals(await apiFetch<Approval[]>("/security/approvals"));
    });
  }

  async function decide(id: string, decision: string) {
    await run(async () => {
      await apiFetch(`/security/approvals/${id}/decision`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ decision, reason: reasons[id] ?? "" }) });
      setNotice(`Request ${decision.toLowerCase()}.`);
      await reload();
    });
  }

  function updateRule(index: number, changes: Partial<Rule>) {
    if (!policy) return;
    setPolicy({ ...policy, rules: policy.rules.map((rule, i) => i === index ? { ...rule, ...changes } : rule) });
  }

  return <PageChrome title="Security Controls" description="Inspect prompts, review approval requests, and manage policy decisions.">
    <section className="single-view">
      {error && <p className="backend-error" role="alert">{error}</p>}
      {notice && <p className="success-state" role="status">{notice}</p>}
      {!user && !error && <p>Loading your permissions…</p>}
      {user && user.role !== "auditor" && <article className="panel tool-panel">
        <h2>Check a prompt</h2>
        <p>Use synthetic data for demonstrations. This workspace checks content; it does not call an AI provider.</p>
        <form className="prompt-form" onSubmit={inspect}>
          <label>AI service<select value={service} onChange={e => setService(e.target.value)}>{["ChatGPT Enterprise", "Google Gemini", "Microsoft Copilot"].map(s => <option key={s}>{s}</option>)}</select></label>
          <label>Prompt<textarea value={prompt} onChange={e => setPrompt(e.target.value)} maxLength={10000} required /></label>
          <button disabled={busy} type="submit">Check policy</button>
        </form>
        {result && <div role="status"><h3>{result.decision.replaceAll("_", " ")}</h3><p>{result.policyRule} · Policy version {result.policy_version}</p><p>{result.send_allowed ? "Permitted content is ready for the gateway integration." : "Submission is stopped."}</p><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{result.maskedOutput}</pre></div>}
      </article>}
      <article className="panel tool-panel">
        <div className="panel-heading"><h2>Approval requests</h2><button disabled={busy} onClick={() => void run(reload)}>Refresh</button></div>
        <p>Reviewers see sanitized content only. Requests expire after one hour; a policy change invalidates release.</p>
        {!approvals.length && <p>No requests to review.</p>}
        {approvals.map(a => <section key={a.id} style={{ padding: "1rem 0", borderBottom: "1px solid #526079" }}>
          <h3>{a.service} · {a.status}</h3><small>Request {a.id} · Policy {a.policy_version}</small>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{a.sanitized_prompt}</pre>
          {a.reason && <p>{a.reason}</p>}
          {a.status === "PENDING" && (user?.role === "admin" || user?.role === "approver") && user.id !== a.requester && <div className="prompt-form">
            <label>Review reason<input maxLength={500} value={reasons[a.id] ?? ""} onChange={e => setReasons({ ...reasons, [a.id]: e.target.value })} /></label>
            <button disabled={busy || !reasons[a.id]?.trim()} onClick={() => void decide(a.id, "APPROVED")}>Approve sanitized content</button>
            <button disabled={busy || !reasons[a.id]?.trim()} onClick={() => void decide(a.id, "REJECTED")}>Reject</button>
          </div>}
          {a.status === "APPROVED" && user?.id === a.requester && <button disabled={busy} onClick={() => void run(async () => {
            const released = await apiFetch<{ sanitized_prompt: string }>(`/security/approvals/${a.id}/consume`, { method: "POST" });
            setResult({ decision: "SANITIZE", send_allowed: true, maskedOutput: released.sanitized_prompt, policyRule: "Approved content released once", policy_version: a.policy_version });
            setNotice("Approved content released in the prompt result. It has not been sent to an AI service."); await reload();
          })}>Release approved content once</button>}
        </section>)}
      </article>
      <article className="panel tool-panel">
        <h2>Policy rules {policy && `· Version ${policy.version}`}</h2>
        <p>Credentials and critical risk always block. For matching rules, block overrides approval, which overrides sanitization. An uncovered sensitive category blocks.</p>
        {policy?.rules.map((r, index) => <fieldset className="prompt-form" key={r.id} disabled={user?.role !== "admin" || busy} style={{ marginBottom: "1rem", padding: "1rem" }}>
          <legend>{r.name}</legend><p>{r.category}</p>
          <label>Action<select value={r.action} onChange={e => updateRule(index, { action: e.target.value })}>{(r.category === "Credentials & Secrets" ? ["BLOCK"] : ["SANITIZE", "BLOCK", "REQUIRE_APPROVAL"]).map(a => <option key={a}>{a}</option>)}</select></label>
          <label>Minimum risk score<input type="number" min={0} max={100} value={r.min_score} onChange={e => updateRule(index, { min_score: Number(e.target.value) })} /></label>
          <label>Maximum risk score<input type="number" min={0} max={100} value={r.max_score} onChange={e => updateRule(index, { max_score: Number(e.target.value) })} /></label>
          <label><input type="checkbox" checked={r.enabled} onChange={e => updateRule(index, { enabled: e.target.checked })} /> Enabled</label>
          <p>Roles: {r.roles.join(", ")} · Services: {r.services.join(", ")}</p>
        </fieldset>)}
        {user?.role === "admin" && <button disabled={busy || !policy} onClick={() => void run(async () => {
          const saved = await apiFetch<Policy>("/security/policy", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ expected_version: policy?.version, rules: policy?.rules }) });
          setPolicy(saved); setNotice(`Policy version ${saved.version} saved. Existing approval releases require resubmission.`);
        })}>Save policy version</button>}
      </article>
      <article className="panel tool-panel">
        <h2>Change your password</h2>
        <form className="prompt-form" onSubmit={event => { event.preventDefault(); void run(async () => {
          await apiFetch("/auth/password", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) });
          setCurrentPassword(""); setNewPassword(""); window.location.href = "/login";
        }); }}>
          <label>Current password<input type="password" autoComplete="current-password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} maxLength={128} required /></label>
          <label>New password<input type="password" autoComplete="new-password" value={newPassword} onChange={e => setNewPassword(e.target.value)} minLength={12} maxLength={128} required /></label>
          <button disabled={busy} type="submit">Change password and sign out</button>
        </form>
      </article>
    </section>
  </PageChrome>;
}
