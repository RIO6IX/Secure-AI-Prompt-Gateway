import { getD1 } from "../../../db";

export const runtime = "edge";

type RiskLevel = "Low" | "Medium" | "High" | "Critical";

type AuditEventPayload = {
  actor?: string;
  department?: string;
  service?: string;
  action?: string;
  status?: string;
  risk?: RiskLevel;
  riskScore?: number;
  finding?: string;
  category?: string;
  policyRule?: string;
  maskedOutput?: string;
  originalPrompt?: string;
  promptHash?: string;
  source?: string;
};

const createAuditEventsTable = `
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor TEXT NOT NULL,
  department TEXT NOT NULL DEFAULT 'Unknown',
  service TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  risk TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  finding TEXT NOT NULL,
  category TEXT NOT NULL,
  policy_rule TEXT NOT NULL DEFAULT 'Unassigned',
  masked_output TEXT NOT NULL,
  prompt_hash TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'gateway',
  ip_address TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
)`;

async function ensureSchema() {
  const db = getD1();
  await db.batch([
    db.prepare(createAuditEventsTable),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_timestamp_idx ON audit_events (timestamp DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_risk_idx ON audit_events (risk)"),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_category_idx ON audit_events (category)"),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events (actor)"),
  ]);
}

function text(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 600) : fallback;
}

function risk(value: unknown): RiskLevel {
  return value === "Low" || value === "Medium" || value === "High" || value === "Critical"
    ? value
    : "Medium";
}

async function hashPrompt(payload: AuditEventPayload) {
  if (payload.promptHash) {
    return payload.promptHash.slice(0, 128);
  }

  if (!payload.originalPrompt) {
    return "";
  }

  const buffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(payload.originalPrompt),
  );

  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function toRouteError(error: unknown) {
  const message = error instanceof Error ? error.message : "Unexpected backend error";
  return Response.json({ error: message }, { status: 500 });
}

export async function GET() {
  try {
    await ensureSchema();
    const db = getD1();

    const [
      totals,
      categories,
      risks,
      services,
      topUsers,
      recentEvents,
      recentAlerts,
      dataTypes,
      trend,
    ] = await Promise.all([
      db.prepare(
        `SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked,
          SUM(CASE WHEN risk IN ('High', 'Critical') THEN 1 ELSE 0 END) AS highRisk,
          COUNT(DISTINCT actor) AS activeUsers,
          AVG(risk_score) AS averageRiskScore
        FROM audit_events`
      ).first(),
      db.prepare(
        `SELECT category AS name, COUNT(*) AS value
         FROM audit_events
         GROUP BY category
         ORDER BY value DESC`
      ).all(),
      db.prepare(
        `SELECT risk AS name, COUNT(*) AS value
         FROM audit_events
         GROUP BY risk
         ORDER BY CASE risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
      ).all(),
      db.prepare(
        `SELECT service AS name, COUNT(*) AS value
         FROM audit_events
         GROUP BY service
         ORDER BY value DESC`
      ).all(),
      db.prepare(
        `SELECT actor AS name, department, SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked
         FROM audit_events
         GROUP BY actor, department
         ORDER BY blocked DESC, name ASC
         LIMIT 8`
      ).all(),
      db.prepare(
        `SELECT id, timestamp, actor, department, service, action, status, risk, risk_score AS riskScore,
                finding, category, policy_rule AS policyRule, masked_output AS maskedOutput,
                prompt_hash AS promptHash, source, ip_address AS ipAddress, user_agent AS userAgent
         FROM audit_events
         ORDER BY timestamp DESC
         LIMIT 100`
      ).all(),
      db.prepare(
        `SELECT id, timestamp, actor, service, finding, risk, status
         FROM audit_events
         WHERE risk IN ('High', 'Critical') OR status = 'Blocked'
         ORDER BY timestamp DESC
         LIMIT 10`
      ).all(),
      db.prepare(
        `SELECT finding AS name, COUNT(*) AS value
         FROM audit_events
         GROUP BY finding
         ORDER BY value DESC
         LIMIT 10`
      ).all(),
      db.prepare(
        `SELECT substr(timestamp, 1, 10) AS day, category, COUNT(*) AS value
         FROM audit_events
         WHERE timestamp >= datetime('now', '-7 days')
         GROUP BY day, category
         ORDER BY day ASC`
      ).all(),
    ]);

    return Response.json({
      generatedAt: new Date().toISOString(),
      totals,
      categories: categories.results,
      risks: risks.results,
      services: services.results,
      topUsers: topUsers.results,
      recentEvents: recentEvents.results,
      recentAlerts: recentAlerts.results,
      dataTypes: dataTypes.results,
      trend: trend.results,
    });
  } catch (error) {
    return toRouteError(error);
  }
}

export async function POST(request: Request) {
  try {
    await ensureSchema();
    const payload = (await request.json()) as AuditEventPayload;
    const actor = text(payload.actor, "");
    const service = text(payload.service, "");
    const finding = text(payload.finding, "");
    const maskedOutput = text(payload.maskedOutput, "");

    if (!actor || !service || !finding || !maskedOutput) {
      return Response.json(
        { error: "actor, service, finding, and maskedOutput are required" },
        { status: 400 }
      );
    }

    const db = getD1();
    const id = `AUD-${crypto.randomUUID().replaceAll("-", "").slice(0, 10).toUpperCase()}`;
    const timestamp = new Date().toISOString();
    const headers = request.headers;

    await db.prepare(
      `INSERT INTO audit_events
       (id, timestamp, actor, department, service, action, status, risk, risk_score,
        finding, category, policy_rule, masked_output, prompt_hash, source, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        timestamp,
        actor,
        text(payload.department, "Unknown"),
        service,
        text(payload.action, "Prompt inspected"),
        text(payload.status, "Sanitized"),
        risk(payload.risk),
        Math.max(0, Math.min(100, Number(payload.riskScore ?? 50))),
        finding,
        text(payload.category, "Sensitive Data"),
        text(payload.policyRule, "Default prompt leakage policy"),
        maskedOutput,
        await hashPrompt(payload),
        text(payload.source, "gateway"),
        headers.get("cf-connecting-ip") ?? headers.get("x-forwarded-for") ?? "",
        headers.get("user-agent") ?? "",
      )
      .run();

    return Response.json({ id, timestamp }, { status: 201 });
  } catch (error) {
    return toRouteError(error);
  }
}
