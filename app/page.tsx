import type { Metadata } from "next";
import { SecureChatWorkspace } from "./components/SecureChatWorkspace";

export const metadata: Metadata = {
  title: "Secure AI Prompt Gateway",
  description:
    "A private workspace that inspects sensitive prompts before external AI use.",
};

export default function Home() {
  return <SecureChatWorkspace />;
}
