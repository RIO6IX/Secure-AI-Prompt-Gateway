import type { Metadata } from "next";
import { AuthForm } from "../components/AuthForm";

export const metadata: Metadata = {
  title: "Login - Secure AI Prompt Gateway",
};

export default function LoginPage() {
  return <AuthForm mode="login" />;
}
