import { getD1 } from "../../../db";

export const runtime = "edge";

export async function GET() {
  const started = Date.now();

  try {
    const db = getD1();
    await db.prepare("SELECT 1").first();

    return Response.json({
      status: "healthy",
      database: "connected",
      averageResponseMs: Date.now() - started,
      services: [
        { name: "Audit API", state: "Healthy" },
        { name: "D1 Audit Database", state: "Healthy" },
        { name: "Dashboard Reader", state: "Healthy" },
      ],
    });
  } catch (error) {
    return Response.json(
      {
        status: "degraded",
        database: "unavailable",
        error: error instanceof Error ? error.message : "Unknown backend error",
      },
      { status: 503 },
    );
  }
}
