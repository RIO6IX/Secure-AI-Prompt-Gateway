import type { Metadata } from "next";
import { AuditLogsPage } from "../components/StandalonePages";

export const metadata: Metadata = {
  title: "Audit Logs - Secure AI Prompt Gateway",
};

export default function Page() {
  return <AuditLogsPage />;
}
