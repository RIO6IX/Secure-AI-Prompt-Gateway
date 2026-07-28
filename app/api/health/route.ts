import { NextResponse } from "next/server";
import { systemHealth } from "../../lib/security-dashboard-data";

export const runtime = "edge";

export async function GET() {
  return NextResponse.json({
    status: "healthy",
    uptime: "99.98%",
    averageResponseMs: 286,
    services: systemHealth,
  });
}

