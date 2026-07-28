import { NextResponse } from "next/server";
import { auditEvents, highRiskAlerts, policyRules } from "../../lib/security-dashboard-data";

export const runtime = "edge";

export async function GET() {
  return NextResponse.json({
    generatedAt: new Date().toISOString(),
    records: auditEvents,
    alerts: highRiskAlerts,
    policies: policyRules,
  });
}

