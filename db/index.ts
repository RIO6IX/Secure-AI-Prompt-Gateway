import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export function getD1() {
  if (!env.DB) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Set the `d1` field in .openai/hosting.json to `DB` and deploy with Sites before using database-backed audit logs."
    );
  }

  return env.DB;
}

export function getDb() {
  return drizzle(getD1(), { schema });
}
