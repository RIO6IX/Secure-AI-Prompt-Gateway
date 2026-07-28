import type { Metadata } from "next";
import { SystemSettingsPage } from "../components/StandalonePages";

export const metadata: Metadata = {
  title: "System Settings - Secure AI Prompt Gateway",
};

export default function Page() {
  return <SystemSettingsPage />;
}
