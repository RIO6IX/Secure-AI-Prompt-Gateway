import type { Metadata } from "next";
import { AuthForm } from "../components/AuthForm";

export const metadata: Metadata = {
  title: "Register - Secure AI Prompt Gateway",
};

export default function RegisterPage() {
  return <AuthForm mode="register" />;
}
