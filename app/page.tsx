import type { Metadata } from "next";
import { AuditDashboard } from "./components/AuditDashboard";

export const metadata: Metadata = {
  title: "Secure AI Prompt Gateway Dashboard",
  description:
    "Database-backed audit logging and security monitoring dashboard for sensitive prompt leakage prevention.",
};

export default function Home() {
  return <AuditDashboard />;
}
