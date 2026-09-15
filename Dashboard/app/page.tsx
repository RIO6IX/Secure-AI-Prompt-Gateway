import type { Metadata } from "next";
import { SecureGatewayChat } from "./components/SecureGatewayChat";

export const metadata: Metadata = {
  title: "Secure AI Prompt Gateway",
  description:
    "Local secure AI prompt gateway with sensitive data detection, audit logging, and Ollama forwarding.",
};

export default function Home() {
  return <SecureGatewayChat />;
}
