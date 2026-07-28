import { sql } from "drizzle-orm";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const auditEvents = sqliteTable("audit_events", {
  id: text("id").primaryKey(),
  timestamp: text("timestamp").notNull().default(sql`CURRENT_TIMESTAMP`),
  actor: text("actor").notNull(),
  department: text("department").notNull().default("Unknown"),
  service: text("service").notNull(),
  action: text("action").notNull(),
  status: text("status").notNull(),
  risk: text("risk").notNull(),
  riskScore: integer("risk_score").notNull().default(0),
  finding: text("finding").notNull(),
  category: text("category").notNull(),
  policyRule: text("policy_rule").notNull().default("Unassigned"),
  maskedOutput: text("masked_output").notNull(),
  promptHash: text("prompt_hash").notNull().default(""),
  source: text("source").notNull().default("gateway"),
  ipAddress: text("ip_address").notNull().default(""),
  userAgent: text("user_agent").notNull().default(""),
});
