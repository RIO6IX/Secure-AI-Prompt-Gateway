import type { Metadata } from "next";
import { AuditDashboard } from "../../AuditDashboard";

export const metadata: Metadata = {
  title: "Audit Logging Dashboard | Secure AI Prompt Gateway",
  description: "Security dashboard backed by local SQLite audit logs.",
};

export default function DashboardPage() {
  return <AuditDashboard />;
}
