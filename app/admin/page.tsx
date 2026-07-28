import type { Metadata } from "next";
import { AdminPanelPage } from "../components/StandalonePages";

export const metadata: Metadata = {
  title: "Admin Panel - Secure AI Prompt Gateway",
};

export default function Page() {
  return <AdminPanelPage />;
}
